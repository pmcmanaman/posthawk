package validation

import (
	"fmt"
	"net"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
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

// Format validation
func PerformFormatCheck(email string) Check {
	// More comprehensive email format regex based on RFC 5322
	emailRegex := `^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`
	matched, _ := regexp.MatchString(emailRegex, email)

	return Check{
		Name:    "format",
		Passed:  matched,
		Details: "Email format validation",
	}
}

// Length validation
func PerformLengthCheck(localPart, domain string) Check {
	// RFC 5321 limits
	localValid := len(localPart) <= 64
	domainValid := len(domain) <= 255

	return Check{
		Name:    "length",
		Passed:  localValid && domainValid,
		Details: "Email length validation",
	}
}

// Disposable email check
func CheckDisposableEmail(domain string, logger *logrus.Logger) Check {
	// Load disposable domains from file
	data, err := os.ReadFile("backend/disposable_domains.txt")
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Warn("Failed to load disposable domains")
		return Check{
			Name:    "disposable",
			Passed:  true,
			Details: "Failed to load disposable domains list",
		}
	}

	// Convert to map for quick lookup
	disposableDomains := make(map[string]bool)
	for _, d := range strings.Split(string(data), "\n") {
		d = strings.TrimSpace(d)
		if d != "" {
			disposableDomains[d] = true
		}
	}

	// Check if domain is disposable
	if disposableDomains[domain] {
		return Check{
			Name:    "disposable",
			Passed:  false,
			Details: "Disposable email domain detected",
		}
	}

	return Check{
		Name:    "disposable",
		Passed:  true,
		Details: "No disposable email domain detected",
	}
}

// MX record check
func PerformMXCheck(domain string) Check {
	mxRecords, err := net.LookupMX(domain)

	return Check{
		Name:    "mx",
		Passed:  err == nil && len(mxRecords) > 0,
		Details: "MX record validation",
	}
}

// SMTP check
func PerformSMTPCheck(email, domain string, timeout time.Duration, logger *logrus.Logger) Check {
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "No MX records found",
		}
	}

	// Try connecting to first MX server with timeout
	addr := mxRecords[0].Host + ":25"
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"mx":    mxRecords[0].Host,
		}).Debug("SMTP connection failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "Failed to connect to mail server",
		}
	}
	defer conn.Close()

	// Create textproto connection
	tc := textproto.NewConn(conn)
	defer tc.Close()

	// Create SMTP log buffer
	var smtpLog strings.Builder
	logResponse := func(code int, message string) {
		smtpLog.WriteString(fmt.Sprintf("%d %s\n", code, message))
	}

	// Read server greeting
	code, message, err := tc.ReadResponse(220)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP greeting failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP validation failed - greeting",
		}
	}
	logResponse(code, message)

	// Send EHLO
	err = tc.PrintfLine("EHLO posthawk.com")
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP EHLO failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP validation failed - EHLO",
		}
	}
	code, message, err = tc.ReadResponse(250)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP EHLO response failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP EHLO response failed",
		}
	}
	logResponse(code, message)

	// Send MAIL FROM
	err = tc.PrintfLine("MAIL FROM:<verify@posthawk.com>")
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP MAIL FROM failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP MAIL FROM failed",
		}
	}
	code, message, err = tc.ReadResponse(250)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP MAIL FROM response failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP validation failed - MAIL FROM response",
		}
	}
	logResponse(code, message)

	// Send RCPT TO
	err = tc.PrintfLine("RCPT TO:<%s>", email)
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP RCPT TO failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP validation failed - RCPT TO",
		}
	}
	code, message, err = tc.ReadResponse(250)
	if err != nil {
		// Check for IP blocked error
		if strings.Contains(message, "Blocked") {
			logger.WithFields(logrus.Fields{
				"email": email,
				"error": message,
				"cache": "miss",
			}).Debug("SMTP validation blocked - IP blocked")
			return Check{
				Name:    "smtp",
				Passed:  false,
				Details: "SMTP validation uncheckable - IP blocked",
			}
		}
		logger.WithFields(logrus.Fields{
			"error": err.Error(),
			"log":   smtpLog.String(),
		}).Debug("SMTP RCPT TO response failed")
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "SMTP validation failed - RCPT TO response",
		}
	}
	logResponse(code, message)

	// Log full SMTP conversation
	logger.WithFields(logrus.Fields{
		"email": email,
		"log":   smtpLog.String(),
	}).Debug("SMTP validation completed")

	return Check{
		Name:    "smtp",
		Passed:  true,
		Details: "SMTP validation successful",
	}
}

// DNS record check
func PerformDNSCheck(domain string) Check {
	_, err := net.LookupIP(domain)

	return Check{
		Name:    "dns",
		Passed:  err == nil,
		Details: "DNS record validation",
	}
}

// TLD check
func PerformTLDCheck(domain string) Check {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return Check{
			Name:    "tld",
			Passed:  false,
			Details: "Invalid domain format",
		}
	}

	tld := parts[len(parts)-1]
	// Basic check for valid TLD length
	valid := len(tld) >= 2 && len(tld) <= 6

	return Check{
		Name:    "tld",
		Passed:  valid,
		Details: "Top-level domain validation",
	}
}

// Role account check
func PerformRoleAccountCheck(email string) Check {
	// Common role-based prefixes
	rolePrefixes := []string{"admin", "postmaster", "webmaster", "hostmaster", "abuse"}
	localPart := strings.Split(email, "@")[0]

	for _, prefix := range rolePrefixes {
		if strings.HasPrefix(strings.ToLower(localPart), prefix) {
			return Check{
				Name:    "role",
				Passed:  false,
				Details: "Role-based account detected",
			}
		}
	}

	return Check{
		Name:    "role",
		Passed:  true,
		Details: "No role-based account detected",
	}
}

// Free provider check
func PerformFreeProviderCheck(domain string) Check {
	// Common free email providers
	freeProviders := []string{"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}

	for _, provider := range freeProviders {
		if strings.EqualFold(domain, provider) {
			return Check{
				Name:    "free",
				Passed:  false,
				Details: "Free email provider detected",
			}
		}
	}

	return Check{
		Name:    "free",
		Passed:  true,
		Details: "No free email provider detected",
	}
}
