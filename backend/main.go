// PostHawk - Precision Email Validation Service
// Version: 1.0.0
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/rs/cors"
	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"

	"posthawk/backend/config"
	"posthawk/backend/database"
	"posthawk/backend/metrics"
	"posthawk/backend/validation"
)

const (
	VERSION  = config.VERSION
	APP_NAME = config.APP_NAME
)

var (
	logger = logrus.New()
	cfg    = config.LoadConfig(logger)

	// Client-specific rate limiters
	clientLimiters = make(map[string]*rate.Limiter)
)

// Remove local Config type definition since we're using config.Config

type ClientConfig struct {
	RateLimit float64
	RateBurst int
	Name      string
}

type EmailRequest struct {
	Email string `json:"email"`
}

func init() {
	metrics.RegisterMetrics()

	logger.SetFormatter(&logrus.JSONFormatter{
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
	})
}

// tracingMiddleware adds tracing headers and request context
func tracingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Add tracing context
		ctx := context.WithValue(r.Context(), "requestID", requestID)
		ctx = context.WithValue(ctx, "startTime", start)
		r = r.WithContext(ctx)

		// Log request start
		logger.WithFields(logrus.Fields{
			"request_id":   requestID,
			"method":       r.Method,
			"uri":          r.RequestURI,
			"remote_addr":  r.RemoteAddr,
			"user_agent":   r.UserAgent(),
			"content_type": r.Header.Get("Content-Type"),
		}).Info("Request started")

		// Record request size
		if r.ContentLength > 0 {
			metrics.RequestSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(r.ContentLength))
		}

		// Wrap response writer to capture status and size
		ww := newWrappedWriter(w)
		next.ServeHTTP(ww, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		metrics.RequestLatency.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Observe(duration)
		metrics.ResponseSize.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Observe(float64(ww.size))

		// Log request completion
		logger.WithFields(logrus.Fields{
			"request_id":    requestID,
			"method":        r.Method,
			"uri":           r.RequestURI,
			"status":        ww.status,
			"duration_secs": duration,
			"bytes":         ww.size,
		}).Info("Request completed")
	})
}

// wrappedWriter captures response status and size
type wrappedWriter struct {
	http.ResponseWriter
	status int
	size   int
}

func newWrappedWriter(w http.ResponseWriter) *wrappedWriter {
	return &wrappedWriter{ResponseWriter: w}
}

func (w *wrappedWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *wrappedWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	size, err := w.ResponseWriter.Write(b)
	w.size += size
	return size, err
}

func validateEmail(email string, config config.Config, clientID string, logger *logrus.Logger) validation.ValidationResponse {
	// Check cache first
	cachedResponse, err := database.GetCachedValidation(email, logger)
	if err != nil {
		logger.WithError(err).Warn("Failed to check cache")
	} else if cachedResponse != nil {
		// Return cached response if found
		return *cachedResponse
	}

	startTime := time.Now()
	metrics.ActiveRequests.Inc()
	defer metrics.ActiveRequests.Dec()

	response := validation.ValidationResponse{
		Email:          email,
		IsValid:        false,
		Checks:         make([]validation.Check, 0),
		Version:        VERSION,
		ServiceName:    APP_NAME,
		IsRoleAccount:  false,
		IsFreeProvider: false,
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		metrics.ValidationRequests.WithLabelValues("invalid_format", "format", clientID, "").Inc()
		response.Details = "Invalid email format"
		return response
	}
	domain := parts[1]

	// Format check
	formatCheck := validation.PerformFormatCheck(email)
	response.Checks = append(response.Checks, formatCheck)
	if !formatCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("invalid_format", "format", clientID, domain).Inc()
		response.Details = formatCheck.Details
		return response
	}

	// Length checks
	lengthCheck := validation.PerformLengthCheck(parts[0], domain)
	response.Checks = append(response.Checks, lengthCheck)
	if !lengthCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("invalid_length", "length", clientID, domain).Inc()
		response.Details = lengthCheck.Details
		return response
	}

	// Disposable email check
	if config.DisposableCheck {
		disposableCheck := validation.CheckDisposableEmail(domain, logger)
		response.Checks = append(response.Checks, disposableCheck)
		response.IsDisposable = !disposableCheck.Passed
		if response.IsDisposable {
			metrics.ValidationRequests.WithLabelValues("disposable", "disposable", clientID, domain).Inc()
			response.Details = "Disposable email address detected"
			response.RecommendedAction = "Request a different email address"
			return response
		}
	}

	// MX record check
	mxCheck := validation.PerformMXCheck(domain)
	response.Checks = append(response.Checks, mxCheck)
	if !mxCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("mx_failed", "mx", clientID, domain).Inc()
		response.Details = mxCheck.Details
		return response
	}

	// SMTP check
	smtpCheck := validation.PerformSMTPCheck(email, domain, config.SMTPTimeout, logger)
	response.Checks = append(response.Checks, smtpCheck)
	if !smtpCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("smtp_failed", "smtp", clientID, domain).Inc()
		response.Details = smtpCheck.Details
		return response
	}

	// DNS record check
	dnsCheck := validation.PerformDNSCheck(domain)
	response.Checks = append(response.Checks, dnsCheck)
	if !dnsCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("dns_failed", "dns", clientID, domain).Inc()
		response.Details = dnsCheck.Details
		return response
	}

	// TLD check
	tldCheck := validation.PerformTLDCheck(domain)
	response.Checks = append(response.Checks, tldCheck)
	if !tldCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("tld_failed", "tld", clientID, domain).Inc()
		response.Details = tldCheck.Details
		return response
	}

	// Role account check
	roleCheck := validation.PerformRoleAccountCheck(email)
	response.Checks = append(response.Checks, roleCheck)
	response.IsRoleAccount = !roleCheck.Passed

	// Free provider check
	freeCheck := validation.PerformFreeProviderCheck(domain)
	response.Checks = append(response.Checks, freeCheck)
	response.IsFreeProvider = !freeCheck.Passed

	response.IsValid = true
	response.Details = "Email address is valid"
	response.ValidationTime = time.Since(startTime).Seconds()
	metrics.ValidationRequests.WithLabelValues("success", "all", clientID, domain).Inc()
	metrics.ValidationDuration.WithLabelValues("complete", domain).Observe(response.ValidationTime)

	// Store result in cache
	if err := database.StoreValidation(response); err != nil {
		logger.WithError(err).Warn("Failed to store validation result in cache")
	}

	return response
}

func authenticateRequest(r *http.Request, config config.Config) (string, error) {
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		return "", fmt.Errorf("missing API key")
	}

	clientConfig, exists := config.APIKeys[apiKey]
	if !exists {
		return "", fmt.Errorf("invalid API key")
	}

	return clientConfig.Name, nil
}

func emailHandler(w http.ResponseWriter, r *http.Request, config config.Config) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID, err := authenticateRequest(r, config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		logger.WithError(err).Warn("Authentication failed")
		return
	}

	// Get or create client-specific rate limiter
	limiter, exists := clientLimiters[clientID]
	if !exists {
		clientConfig := config.APIKeys[r.Header.Get("X-API-Key")] // Get config using actual API key
		limiter = rate.NewLimiter(rate.Limit(clientConfig.RateLimit), clientConfig.RateBurst)
		clientLimiters[clientID] = limiter
		logger.WithFields(logrus.Fields{
			"client_id":  clientID,
			"rate_limit": clientConfig.RateLimit,
			"burst":      clientConfig.RateBurst,
		}).Debug("Created new rate limiter")
	}

	if !limiter.Allow() {
		metrics.RateLimitExceeded.WithLabelValues(clientID).Inc()
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		logger.WithFields(logrus.Fields{
			"client_id":     clientID,
			"remote_addr":   r.RemoteAddr,
			"current_limit": limiter.Limit(),
			"current_burst": limiter.Burst(),
		}).Warn("Rate limit exceeded")
		return
	}

	var req EmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		logger.WithError(err).Error("Failed to decode request body")
		return
	}

	logger.WithFields(logrus.Fields{
		"email":       req.Email,
		"client_id":   clientID,
		"remote_addr": r.RemoteAddr,
	}).Info("Validation request received")

	result := validateEmail(req.Email, config, clientID, logger)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func loadDisposableDomains() (map[string]bool, error) {
	domains := make(map[string]bool)

	file, err := os.Open("disposable_domains.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to open disposable domains file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading disposable domains file: %w", err)
	}

	return domains, nil
}

func dialSMTP(addr string, timeout time.Duration, logger *logrus.Logger) (*smtp.Client, error) {
	logger.WithFields(logrus.Fields{
		"address": addr,
		"timeout": timeout,
	}).Debug("Attempting SMTP connection")

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error":   err,
			"address": addr,
		}).Debug("SMTP connection failed")
		return nil, err
	}

	logger.Debug("TCP connection established")
	return smtp.NewClient(conn, addr)
}

// batchEmailHandler handles batch email validation requests
func batchEmailHandler(w http.ResponseWriter, r *http.Request, config config.Config) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientID, err := authenticateRequest(r, config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		Emails []string `json:"emails"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if len(req.Emails) > 100 {
		http.Error(w, "Maximum batch size is 100 emails", http.StatusBadRequest)
		return
	}

	results := make([]validation.ValidationResponse, 0, len(req.Emails))
	for _, email := range req.Emails {
		result := validateEmail(email, config, clientID, logger)
		results = append(results, result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// domainReputationHandler provides domain reputation information
func domainReputationHandler(w http.ResponseWriter, r *http.Request, config config.Config) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain parameter is required", http.StatusBadRequest)
		return
	}

	// Basic reputation scoring based on various factors
	score := 100.0

	// Check if disposable domain
	if config.DisposableCheck {
		disposableCheck := validation.CheckDisposableEmail(domain, logger)
		if !disposableCheck.Passed {
			score -= 50
		}
	}

	// Check MX records
	mxCheck := validation.PerformMXCheck(domain)
	if !mxCheck.Passed {
		score -= 20
	}

	// Check DNS records
	dnsCheck := validation.PerformDNSCheck(domain)
	if !dnsCheck.Passed {
		score -= 10
	}

	// Check TLD
	tldCheck := validation.PerformTLDCheck(domain)
	if !tldCheck.Passed {
		score -= 10
	}

	response := map[string]interface{}{
		"domain":  domain,
		"score":   score,
		"rating":  getReputationRating(score),
		"checks":  []validation.Check{mxCheck, dnsCheck, tldCheck},
		"version": VERSION,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func getReputationRating(score float64) string {
	switch {
	case score >= 90:
		return "excellent"
	case score >= 70:
		return "good"
	case score >= 50:
		return "fair"
	case score >= 30:
		return "poor"
	default:
		return "bad"
	}
}

// statsHandler returns service statistics
func statsHandler(w http.ResponseWriter, r *http.Request, config config.Config) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := map[string]interface{}{
		"total_requests":      getCounterValue(metrics.ValidationRequests),
		"active_requests":     getGaugeValue(metrics.ActiveRequests),
		"rate_limit_exceeded": getCounterValue(metrics.RateLimitExceeded),
		"validation_errors":   getCounterValue(metrics.ValidationErrors),
		"version":             VERSION,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func getCounterValue(counter *prometheus.CounterVec) float64 {
	metric := &dto.Metric{}
	if err := counter.With(prometheus.Labels{}).Write(metric); err == nil {
		return metric.Counter.GetValue()
	}
	return 0
}

func getGaugeValue(gauge prometheus.Gauge) float64 {
	metric := &dto.Metric{}
	if err := gauge.Write(metric); err == nil {
		return metric.Gauge.GetValue()
	}
	return 0
}

func main() {
	// Initialize database
	err := database.InitDatabase()
	if err != nil {
		logger.WithError(err).Fatal("Failed to initialize database")
	}
	defer func() {
		if err := database.CloseDatabase(); err != nil {
			logger.WithError(err).Error("Failed to close database")
		}
	}()

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(level)

	mux := http.NewServeMux()

	// Serve static files from the root directory
	fs := http.FileServer(http.Dir("../"))
	mux.Handle("/", fs)

	// Add middleware
	handler := tracingMiddleware(mux)

	// Versioned API endpoints
	v1 := http.NewServeMux()

	// Main validation endpoint
	v1.HandleFunc("/v1/validate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		emailHandler(w, r, cfg)
	})

	// Simple validation endpoint for frontend
	v1.HandleFunc("/v1/check-email", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Use existing validation logic
		result := validateEmail(req.Email, cfg, "frontend", logger)

		// Return simplified response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":   result.IsValid,
			"message": result.Details,
		})
	})

	// Batch validation endpoint
	v1.HandleFunc("/v1/validate/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		batchEmailHandler(w, r, cfg)
	})

	// Domain reputation endpoint
	v1.HandleFunc("/v1/domain/reputation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		domainReputationHandler(w, r, cfg)
	})

	// Mount versioned API
	mux.Handle("/v1/", v1)

	// Prometheus metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"version": VERSION,
			"name":    APP_NAME,
		})
	})

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"version": VERSION,
		})
	})

	// Statistics endpoint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		statsHandler(w, r, cfg)
	})

	// Add CORS middleware
	handler = cors.New(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"POST", "GET", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-API-Key", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any major browser
	}).Handler(handler)

	// Start server
	serverAddr := ":" + cfg.Port
	logger.WithFields(logrus.Fields{
		"port":    cfg.Port,
		"version": VERSION,
		"name":    APP_NAME,
	}).Info("Starting server")

	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		logger.Fatal(err)
	}
}
