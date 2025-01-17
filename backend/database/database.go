package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"posthawk/backend/validation"

	"github.com/sirupsen/logrus"
	_ "modernc.org/sqlite"
)

const (
	// Cache TTL in hours
	cacheTTL = 24
	// Database file path
	dbPath = "posthawk_cache.db"
)

var (
	db *sql.DB
)

// ValidationCache represents a cached validation result
type ValidationCache struct {
	Email        string
	Response     validation.ValidationResponse
	CreatedAt    time.Time
	LastAccessed time.Time
}

// InitDatabase initializes the SQLite database
func InitDatabase() error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Create tables if they don't exist
	query := `CREATE TABLE IF NOT EXISTS validation_cache (
		email TEXT PRIMARY KEY,
		response TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		last_accessed DATETIME NOT NULL
	);`

	_, err = db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Create index for faster lookups
	_, err = db.Exec("CREATE INDEX IF NOT EXISTS idx_last_accessed ON validation_cache(last_accessed);")
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}

	return nil
}

// GetCachedValidation retrieves a cached validation result
func GetCachedValidation(email string, logger *logrus.Logger) (*validation.ValidationResponse, error) {
	if db == nil {
		return nil, errors.New("database not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var responseJSON string
	var lastAccessed time.Time
	err := db.QueryRowContext(ctx,
		"SELECT response, last_accessed FROM validation_cache WHERE email = ?",
		email).Scan(&responseJSON, &lastAccessed)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			logger.WithFields(logrus.Fields{
				"email": email,
				"cache": "miss",
			}).Debug("Cache miss")
			return nil, nil // Cache miss
		}
		return nil, fmt.Errorf("failed to query cache: %w", err)
	}

	// Check if cache entry is expired
	if time.Since(lastAccessed).Hours() > cacheTTL {
		// Delete expired entry
		_, err := db.ExecContext(ctx, "DELETE FROM validation_cache WHERE email = ?", email)
		if err != nil {
			return nil, fmt.Errorf("failed to delete expired cache: %w", err)
		}
		return nil, nil
	}

	// Update last accessed time
	_, err = db.ExecContext(ctx,
		"UPDATE validation_cache SET last_accessed = ? WHERE email = ?",
		time.Now().UTC(), email)
	if err != nil {
		return nil, fmt.Errorf("failed to update last accessed time: %w", err)
	}

	// Unmarshal response
	logger.WithFields(logrus.Fields{
		"email": email,
		"cache": "hit",
	}).Debug("Cache hit")
	var response validation.ValidationResponse
	err = json.Unmarshal([]byte(responseJSON), &response)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cached response: %w", err)
	}

	return &response, nil
}

// StoreValidation stores a validation result in cache
func StoreValidation(response validation.ValidationResponse) error {
	if db == nil {
		return errors.New("database not initialized")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	responseJSON, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	now := time.Now().UTC()
	_, err = db.ExecContext(ctx,
		`INSERT INTO validation_cache (email, response, created_at, last_accessed)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(email) DO UPDATE SET
			response = excluded.response,
			last_accessed = excluded.last_accessed`,
		response.Email, string(responseJSON), now, now)

	if err != nil {
		return fmt.Errorf("failed to store validation: %w", err)
	}

	return nil
}

// CloseDatabase closes the database connection
func CloseDatabase() error {
	if db != nil {
		return db.Close()
	}
	return nil
}
