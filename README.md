# PostHawk Documentation

## Overview
PostHawk is a precision email validation service that provides comprehensive email verification through multiple validation checks. It's designed as a high-performance, containerized Go application with built-in metrics and rate limiting.

## API Documentation (v1)

### Endpoints

#### POST /v1/validate
Validates an email address

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "email": "user@example.com",
  "is_valid": true,
  "details": "Email address is valid",
  "is_disposable": false,
  "validation_time": 0.123,
  "checks": [
    {
      "name": "format",
      "passed": true
    },
    {
      "name": "length",
      "passed": true
    },
    {
      "name": "mx",
      "passed": true
    },
    {
      "name": "smtp",
      "passed": true
    }
  ],
  "version": "1.0.0",
  "service_name": "PostHawk"
}
```

#### POST /v1/validate/batch
Validates up to 100 email addresses in a single request

**Request:**
```json
{
  "emails": ["user1@example.com", "user2@example.com"]
}
```

**Response:**
```json
[
  {
    "email": "user1@example.com",
    "is_valid": true,
    "details": "Email address is valid",
    ...
  },
  {
    "email": "user2@example.com",
    "is_valid": false,
    "details": "Invalid email format",
    ...
  }
]
```

#### GET /v1/domain/reputation
Provides domain reputation information

**Request:**
```
GET /v1/domain/reputation?domain=example.com
```

**Response:**
```json
{
  "domain": "example.com",
  "score": 85.0,
  "rating": "good",
  "checks": [
    {
      "name": "mx",
      "passed": true
    },
    {
      "name": "dns",
      "passed": true
    }
  ],
  "version": "1.0.0"
}
```

#### GET /v1/stats
Returns service statistics

**Response:**
```json
{
  "total_requests": 1234,
  "active_requests": 5,
  "rate_limit_exceeded": 12,
  "validation_errors": 34,
  "version": "1.0.0"
}
```

#### GET /v1/health
Health check endpoint

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

#### GET /v1/version
Returns service version information

**Response:**
```json
{
  "version": "1.0.0",
  "name": "PostHawk"
}
```

## Configuration

The service is configured through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | HTTP port to listen on | 8080 |
| RATE_LIMIT | Default requests per second | 5 |
| RATE_BURST | Default burst rate | 10 |
| SMTP_TIMEOUT | SMTP connection timeout in seconds | 10 |
| ALLOWED_ORIGINS | Comma-separated list of allowed CORS origins | * |
| LOG_LEVEL | Logging level (debug, info, warn, error) | debug |
| CHECK_DISPOSABLE | Enable disposable email check | true |
| API_KEYS | API key configuration (see below) | - |

### API Key Configuration
API keys are configured through the API_KEYS environment variable in the format:
```
key1:rate_limit:burst:name,key2:rate_limit:burst:name
```

Example:
```
API_KEYS=abc123:10:20:ClientA,def456:5:10:ClientB
```

## Validation Process

The validation process performs these checks in sequence:

1. **Format Validation**
   - Validates email format using regex
   - Checks for valid characters and structure

2. **Length Validation**
   - Validates local part (≤64 chars)
   - Validates domain part (≤255 chars)

3. **Disposable Email Check**
   - Checks against known disposable email domains
   - Can be disabled via CHECK_DISPOSABLE

4. **MX Record Validation**
   - Verifies domain has valid MX records
   - Ensures domain can receive email

5. **SMTP Validation**
   - Attempts SMTP connection to mail server
   - Verifies email address is accepted

## Metrics and Monitoring

The service exposes Prometheus metrics:

- `posthawk_validation_requests_total`
- `posthawk_validation_duration_seconds`
- `posthawk_active_requests`
- `posthawk_rate_limit_exceeded_total`

Metrics are available at `/metrics` endpoint.

## Rate Limiting

- Each API key has configurable rate limits
- Limits are enforced per client
- Exceeded requests return 429 status
- Rate limit metrics are tracked

## Deployment

### Docker
The service is containerized and can be run using Docker:

```bash
docker build -t posthawk .
docker run -p 8080:8080 posthawk
```

### Environment Variables
All configuration is done through environment variables. Example:

```bash
PORT=8080 \
RATE_LIMIT=10 \
RATE_BURST=20 \
API_KEYS="abc123:10:20:ClientA" \
docker run -p 8080:8080 posthawk
```

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| PORT | HTTP port | 8080 |
| RATE_LIMIT | Requests per second | 5 |
| RATE_BURST | Burst rate | 10 |
| SMTP_TIMEOUT | SMTP timeout (seconds) | 10 |
| ALLOWED_ORIGINS | CORS origins | * |
| LOG_LEVEL | Logging level | debug |
| CHECK_DISPOSABLE | Disposable email check | true |
| API_KEYS | API key configuration | - |
