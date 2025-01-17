package validation

import (
	"net"
	"net/smtp"
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
	// Basic email format regex
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
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
	// This would check against a list of known disposable domains
	// For now, just return true (passed) as a placeholder
	return Check{
		Name:    "disposable",
		Passed:  true,
		Details: "Disposable email check",
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

	// Try connecting to first MX server
	addr := mxRecords[0].Host + ":25"
	client, err := smtp.Dial(addr)
	if err != nil {
		return Check{
			Name:    "smtp",
			Passed:  false,
			Details: "Failed to connect to mail server",
		}
	}
	defer client.Close()

	return Check{
		Name:    "smtp",
		Passed:  true,
		Details: "SMTP server validation",
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
