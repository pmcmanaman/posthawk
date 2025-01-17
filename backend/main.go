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
	"regexp"
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
	"posthawk/backend/metrics"
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

type ValidationResponse struct {
	Email             string  `json:"email"`
	IsValid           bool    `json:"is_valid"`
	Details           string  `json:"details"`
	IsDisposable      bool    `json:"is_disposable,omitempty"`
	IsRoleAccount     bool    `json:"is_role_account,omitempty"`
	IsFreeProvider    bool    `json:"is_free_provider,omitempty"`
	ValidationTime    float64 `json:"validation_time"`
	Checks            []Check `json:"checks"`
	RecommendedAction string  `json:"recommended_action,omitempty"`
	Version           string  `json:"version"`
	ServiceName       string  `json:"service_name"`
}

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
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

func validateEmail(email string, config config.Config, clientID string) ValidationResponse {
	startTime := time.Now()
	metrics.ActiveRequests.Inc()
	defer metrics.ActiveRequests.Dec()

	response := ValidationResponse{
		Email:          email,
		IsValid:        false,
		Checks:         make([]Check, 0),
		Version:        VERSION,
		ServiceName:    APP_NAME,
		IsRoleAccount:  false,
		IsFreeProvider: false,
	}

	// Format check
	formatCheck := performFormatCheck(email)
	response.Checks = append(response.Checks, formatCheck)
	if !formatCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("invalid_format", "format", clientID).Inc()
		response.Details = formatCheck.Details
		return response
	}

	parts := strings.Split(email, "@")
	domain := parts[1]

	// Length checks
	lengthCheck := performLengthCheck(parts[0], domain)
	response.Checks = append(response.Checks, lengthCheck)
	if !lengthCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("invalid_length", "length", clientID).Inc()
		response.Details = lengthCheck.Details
		return response
	}

	// Disposable email check
	if config.DisposableCheck {
		disposableCheck := checkDisposableEmail(domain)
		response.Checks = append(response.Checks, disposableCheck)
		response.IsDisposable = !disposableCheck.Passed
		if response.IsDisposable {
			metrics.ValidationRequests.WithLabelValues("disposable", "disposable", clientID).Inc()
			response.Details = "Disposable email address detected"
			response.RecommendedAction = "Request a different email address"
			return response
		}
	}

	// MX record check
	mxCheck := performMXCheck(domain)
	response.Checks = append(response.Checks, mxCheck)
	if !mxCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("mx_failed", "mx", clientID).Inc()
		response.Details = mxCheck.Details
		return response
	}

	// SMTP check
	smtpCheck := performSMTPCheck(email, domain, config.SMTPTimeout)
	response.Checks = append(response.Checks, smtpCheck)
	if !smtpCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("smtp_failed", "smtp", clientID).Inc()
		response.Details = smtpCheck.Details
		return response
	}

	// DNS record check
	dnsCheck := performDNSCheck(domain)
	response.Checks = append(response.Checks, dnsCheck)
	if !dnsCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("dns_failed", "dns", clientID).Inc()
		response.Details = dnsCheck.Details
		return response
	}

	// TLD check
	tldCheck := performTLDCheck(domain)
	response.Checks = append(response.Checks, tldCheck)
	if !tldCheck.Passed {
		metrics.ValidationRequests.WithLabelValues("tld_failed", "tld", clientID).Inc()
		response.Details = tldCheck.Details
		return response
	}

	// Role account check
	roleCheck := performRoleAccountCheck(email)
	response.Checks = append(response.Checks, roleCheck)
	response.IsRoleAccount = !roleCheck.Passed

	// Free provider check
	freeCheck := performFreeProviderCheck(domain)
	response.Checks = append(response.Checks, freeCheck)
	response.IsFreeProvider = !freeCheck.Passed

	response.IsValid = true
	response.Details = "Email address is valid"
	response.ValidationTime = time.Since(startTime).Seconds()
	metrics.ValidationRequests.WithLabelValues("success", "all", clientID).Inc()
	metrics.ValidationDuration.WithLabelValues("complete").Observe(response.ValidationTime)

	return response
}

func performDNSCheck(domain string) Check {
	check := Check{
		Name:   "dns",
		Passed: false,
	}

	// Check A records
	_, err := net.LookupIP(domain)
	if err != nil {
		check.Details = "No A/AAAA records found"
		return check
	}

	check.Passed = true
	return check
}

func performTLDCheck(domain string) Check {
	check := Check{
		Name:   "tld",
		Passed: false,
	}

	// Get TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		check.Details = "Invalid domain format"
		return check
	}
	tld := parts[len(parts)-1]

	// List of valid TLDs
	validTLDs := map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		// Add more TLDs as needed
	}

	if !validTLDs[tld] {
		check.Details = "Unsupported top-level domain"
		return check
	}

	check.Passed = true
	return check
}

func performRoleAccountCheck(email string) Check {
	check := Check{
		Name:   "role_account",
		Passed: true,
	}

	// Common role-based prefixes
	rolePrefixes := []string{
		"admin", "contact", "info", "support", "sales",
		"webmaster", "postmaster", "hostmaster", "abuse",
	}

	localPart := strings.Split(email, "@")[0]
	for _, prefix := range rolePrefixes {
		if strings.HasPrefix(strings.ToLower(localPart), prefix) {
			check.Passed = false
			check.Details = "Role-based account detected"
			break
		}
	}

	return check
}

func performFreeProviderCheck(domain string) Check {
	check := Check{
		Name:   "free_provider",
		Passed: true,
	}

	// List of free email providers
	freeProviders := map[string]bool{
		"gmail.com":      true,
		"yahoo.com":      true,
		"hotmail.com":    true,
		"outlook.com":    true,
		"aol.com":        true,
		"protonmail.com": true,
		// Add more providers as needed
	}

	if freeProviders[domain] {
		check.Passed = false
		check.Details = "Free email provider detected"
	}

	return check
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

	result := validateEmail(req.Email, config, clientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func performFormatCheck(email string) Check {
	check := Check{
		Name:   "format",
		Passed: false,
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(email) {
		check.Details = "Invalid email format"
		return check
	}

	check.Passed = true
	return check
}

func performLengthCheck(local, domain string) Check {
	check := Check{
		Name:   "length",
		Passed: false,
	}

	if len(local) > 64 {
		check.Details = "Local part exceeds 64 characters"
		return check
	}

	if len(domain) > 255 {
		check.Details = "Domain exceeds 255 characters"
		return check
	}

	check.Passed = true
	return check
}

func performMXCheck(domain string) Check {
	check := Check{
		Name:   "mx",
		Passed: false,
	}

	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		check.Details = "Could not find valid MX records"
		return check
	}

	if len(mxRecords) == 0 {
		check.Details = "No MX records found"
		return check
	}

	check.Passed = true
	return check
}

func performSMTPCheck(email, domain string, timeout time.Duration) Check {
	check := Check{
		Name:   "smtp",
		Passed: false,
	}

	mxRecords, _ := net.LookupMX(domain)
	if len(mxRecords) == 0 {
		logger.WithField("domain", domain).Debug("No MX records available")
		check.Details = "No MX records available"
		return check
	}

	logger.WithFields(logrus.Fields{
		"domain":  domain,
		"mx_host": mxRecords[0].Host,
		"email":   email,
	}).Debug("Starting SMTP check")

	client, err := dialSMTP(mxRecords[0].Host+":25", timeout)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err,
			"host":  mxRecords[0].Host,
		}).Debug("Could not connect to mail server")
		check.Details = "Could not connect to mail server"
		return check
	}
	defer client.Close()

	// HELO
	if err := client.Hello("localhost"); err != nil {
		logger.WithFields(logrus.Fields{
			"error":   err,
			"command": "HELO localhost",
		}).Debug("SMTP HELO failed")
		check.Details = "SMTP HELO failed"
		return check
	}
	logger.WithField("command", "HELO localhost").Debug("SMTP command successful")

	// MAIL FROM
	if err := client.Mail("validate@localhost"); err != nil {
		logger.WithFields(logrus.Fields{
			"error":   err,
			"command": "MAIL FROM:<validate@localhost>",
		}).Debug("SMTP MAIL FROM failed")
		check.Details = "SMTP MAIL FROM failed"
		return check
	}
	logger.WithField("command", "MAIL FROM:<validate@localhost>").Debug("SMTP command successful")

	// RCPT TO
	if err := client.Rcpt(email); err != nil {
		logger.WithFields(logrus.Fields{
			"error":   err,
			"command": "RCPT TO:<" + email + ">",
		}).Debug("SMTP RCPT TO failed")
		check.Details = "Email address rejected"
		return check
	}
	logger.WithField("command", "RCPT TO:<"+email+">").Debug("SMTP command successful")

	logger.WithField("email", email).Debug("SMTP validation successful")
	check.Passed = true
	return check
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

func checkDisposableEmail(domain string) Check {
	check := Check{
		Name:   "disposable",
		Passed: true,
	}

	disposableDomains, err := loadDisposableDomains()
	if err != nil {
		logger.WithError(err).Error("Failed to load disposable domains")
		check.Details = "Temporary validation error"
		return check
	}

	if disposableDomains[domain] {
		check.Passed = false
		check.Details = "Disposable email domain detected"
	}

	return check
}

func dialSMTP(addr string, timeout time.Duration) (*smtp.Client, error) {
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

	results := make([]ValidationResponse, 0, len(req.Emails))
	for _, email := range req.Emails {
		result := validateEmail(email, config, clientID)
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
		disposableCheck := checkDisposableEmail(domain)
		if !disposableCheck.Passed {
			score -= 50
		}
	}

	// Check MX records
	mxCheck := performMXCheck(domain)
	if !mxCheck.Passed {
		score -= 20
	}

	// Check DNS records
	dnsCheck := performDNSCheck(domain)
	if !dnsCheck.Passed {
		score -= 10
	}

	// Check TLD
	tldCheck := performTLDCheck(domain)
	if !tldCheck.Passed {
		score -= 10
	}

	response := map[string]interface{}{
		"domain":  domain,
		"score":   score,
		"rating":  getReputationRating(score),
		"checks":  []Check{mxCheck, dnsCheck, tldCheck},
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
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(level)

	mux := http.NewServeMux()

	// Add middleware
	handler := tracingMiddleware(mux)

	// Versioned API endpoints
	v1 := http.NewServeMux()

	// Main validation endpoint
	v1.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		emailHandler(w, r, cfg)
	})

	// Batch validation endpoint
	v1.HandleFunc("/validate/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		batchEmailHandler(w, r, cfg)
	})

	// Domain reputation endpoint
	v1.HandleFunc("/domain/reputation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		domainReputationHandler(w, r, cfg)
	})

	// Mount versioned API
	mux.Handle("/v1/", http.StripPrefix("/v1", v1))

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
