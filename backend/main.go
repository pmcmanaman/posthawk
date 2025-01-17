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
)

const (
	VERSION  = "1.0.0"
	APP_NAME = "PostHawk"
)

var (
	logger = logrus.New()

	// Prometheus metrics
	validationRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_validation_requests_total",
			Help: "Total number of email validation requests",
		},
		[]string{"status", "validation_type", "client_id", "domain"},
	)

	validationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "posthawk_validation_duration_seconds",
			Help:    "Time spent validating emails",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"validation_type", "domain"},
	)

	activeRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "posthawk_active_requests",
			Help: "Number of active validation requests",
		},
	)

	rateLimitExceeded = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_rate_limit_exceeded_total",
			Help: "Number of times rate limit was exceeded",
		},
		[]string{"client_id", "domain"},
	)

	validationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "posthawk_validation_errors_total",
			Help: "Total number of validation errors",
		},
		[]string{"type", "client_id", "domain"},
	)

	requestLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "posthawk_request_latency_seconds",
			Help:    "Request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "status"},
	)

	requestSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "posthawk_request_size_bytes",
			Help: "Request size in bytes",
		},
		[]string{"method", "endpoint"},
	)

	responseSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "posthawk_response_size_bytes",
			Help: "Response size in bytes",
		},
		[]string{"method", "endpoint", "status"},
	)

	// Client-specific rate limiters
	clientLimiters = make(map[string]*rate.Limiter)
)

type Config struct {
	Port            string
	RateLimit       float64
	RateBurst       int
	SMTPTimeout     time.Duration
	AllowedOrigins  []string
	LogLevel        string
	DisposableCheck bool
	APIKeys         map[string]ClientConfig
}

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
	prometheus.MustRegister(
		validationRequests,
		validationDuration,
		activeRequests,
		rateLimitExceeded,
		validationErrors,
		requestLatency,
		requestSize,
		responseSize,
	)

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
			requestSize.WithLabelValues(r.Method, r.URL.Path).Observe(float64(r.ContentLength))
		}

		// Wrap response writer to capture status and size
		ww := newWrappedWriter(w)
		next.ServeHTTP(ww, r)

		// Record metrics
		duration := time.Since(start).Seconds()
		requestLatency.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Observe(duration)
		responseSize.WithLabelValues(r.Method, r.URL.Path, strconv.Itoa(ww.status)).Observe(float64(ww.size))

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

func loadConfig() Config {
	apiKeys := make(map[string]ClientConfig)
	if keysStr := getEnv("API_KEYS", ""); keysStr != "" {
		logger.WithField("api_keys_str", keysStr).Debug("Loading API keys")
		for _, pair := range strings.Split(keysStr, ",") {
			parts := strings.Split(pair, ":")
			if len(parts) == 4 {
				rateLimit, _ := strconv.ParseFloat(parts[1], 64)
				burst, _ := strconv.Atoi(parts[2])
				apiKeys[parts[0]] = ClientConfig{
					RateLimit: rateLimit,
					RateBurst: burst,
					Name:      parts[3],
				}
				logger.WithFields(logrus.Fields{
					"key":        parts[0],
					"rate_limit": rateLimit,
					"burst":      burst,
					"name":       parts[3],
				}).Debug("Loaded API key config")
			}
		}
	}

	config := Config{
		Port:            getEnv("PORT", "8080"),
		RateLimit:       getEnvFloat("RATE_LIMIT", 5),
		RateBurst:       getEnvInt("RATE_BURST", 10),
		SMTPTimeout:     time.Duration(getEnvInt("SMTP_TIMEOUT", 10)) * time.Second,
		AllowedOrigins:  strings.Split(getEnv("ALLOWED_ORIGINS", "*"), ","),
		LogLevel:        getEnv("LOG_LEVEL", "debug"),
		DisposableCheck: getEnvBool("CHECK_DISPOSABLE", true),
		APIKeys:         apiKeys,
	}

	logger.WithFields(logrus.Fields{
		"api_keys_count": len(apiKeys),
		"rate_limit":     config.RateLimit,
		"burst":          config.RateBurst,
	}).Info("Configuration loaded")

	return config
}

func validateEmail(email string, config Config, clientID string) ValidationResponse {
	startTime := time.Now()
	activeRequests.Inc()
	defer activeRequests.Dec()

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
		validationRequests.WithLabelValues("invalid_format", "format", clientID).Inc()
		response.Details = formatCheck.Details
		return response
	}

	parts := strings.Split(email, "@")
	domain := parts[1]

	// Length checks
	lengthCheck := performLengthCheck(parts[0], domain)
	response.Checks = append(response.Checks, lengthCheck)
	if !lengthCheck.Passed {
		validationRequests.WithLabelValues("invalid_length", "length", clientID).Inc()
		response.Details = lengthCheck.Details
		return response
	}

	// Disposable email check
	if config.DisposableCheck {
		disposableCheck := checkDisposableEmail(domain)
		response.Checks = append(response.Checks, disposableCheck)
		response.IsDisposable = !disposableCheck.Passed
		if response.IsDisposable {
			validationRequests.WithLabelValues("disposable", "disposable", clientID).Inc()
			response.Details = "Disposable email address detected"
			response.RecommendedAction = "Request a different email address"
			return response
		}
	}

	// MX record check
	mxCheck := performMXCheck(domain)
	response.Checks = append(response.Checks, mxCheck)
	if !mxCheck.Passed {
		validationRequests.WithLabelValues("mx_failed", "mx", clientID).Inc()
		response.Details = mxCheck.Details
		return response
	}

	// SMTP check
	smtpCheck := performSMTPCheck(email, domain, config.SMTPTimeout)
	response.Checks = append(response.Checks, smtpCheck)
	if !smtpCheck.Passed {
		validationRequests.WithLabelValues("smtp_failed", "smtp", clientID).Inc()
		response.Details = smtpCheck.Details
		return response
	}

	// DNS record check
	dnsCheck := performDNSCheck(domain)
	response.Checks = append(response.Checks, dnsCheck)
	if !dnsCheck.Passed {
		validationRequests.WithLabelValues("dns_failed", "dns", clientID).Inc()
		response.Details = dnsCheck.Details
		return response
	}

	// TLD check
	tldCheck := performTLDCheck(domain)
	response.Checks = append(response.Checks, tldCheck)
	if !tldCheck.Passed {
		validationRequests.WithLabelValues("tld_failed", "tld", clientID).Inc()
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
	validationRequests.WithLabelValues("success", "all", clientID).Inc()
	validationDuration.WithLabelValues("complete").Observe(response.ValidationTime)

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

func authenticateRequest(r *http.Request, config Config) (string, error) {
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

func emailHandler(w http.ResponseWriter, r *http.Request, config Config) {
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
		rateLimitExceeded.WithLabelValues(clientID).Inc()
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

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	strValue := getEnv(key, "")
	if value, err := strconv.Atoi(strValue); err == nil {
		return value
	}
	return fallback
}

func getEnvFloat(key string, fallback float64) float64 {
	strValue := getEnv(key, "")
	if value, err := strconv.ParseFloat(strValue, 64); err == nil {
		return value
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	strValue := getEnv(key, "")
	if value, err := strconv.ParseBool(strValue); err == nil {
		return value
	}
	return fallback
}

// batchEmailHandler handles batch email validation requests
func batchEmailHandler(w http.ResponseWriter, r *http.Request, config Config) {
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
func domainReputationHandler(w http.ResponseWriter, r *http.Request, config Config) {
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
func statsHandler(w http.ResponseWriter, r *http.Request, config Config) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := map[string]interface{}{
		"total_requests":      getCounterValue(validationRequests),
		"active_requests":     getGaugeValue(activeRequests),
		"rate_limit_exceeded": getCounterValue(rateLimitExceeded),
		"validation_errors":   getCounterValue(validationErrors),
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
	config := loadConfig()

	level, err := logrus.ParseLevel(config.LogLevel)
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
		emailHandler(w, r, config)
	})

	// Batch validation endpoint
	v1.HandleFunc("/validate/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		batchEmailHandler(w, r, config)
	})

	// Domain reputation endpoint
	v1.HandleFunc("/domain/reputation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-API-Version", "v1")
		domainReputationHandler(w, r, config)
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
		statsHandler(w, r, config)
	})

	// Add CORS middleware
	handler = cors.New(cors.Options{
		AllowedOrigins:   config.AllowedOrigins,
		AllowedMethods:   []string{"POST", "GET", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "X-API-Key", "X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any major browser
	}).Handler(handler)

	// Start server
	serverAddr := ":" + config.Port
	logger.WithFields(logrus.Fields{
		"port":    config.Port,
		"version": VERSION,
		"name":    APP_NAME,
	}).Info("Starting server")

	if err := http.ListenAndServe(serverAddr, handler); err != nil {
		logger.Fatal(err)
	}
}
