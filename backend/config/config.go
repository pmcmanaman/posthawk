package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	VERSION  = "1.0.0"
	APP_NAME = "PostHawk"
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

func LoadConfig(logger *logrus.Logger) Config {
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
