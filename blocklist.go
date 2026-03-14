package blocklist

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

const (

	// contextTimeout defines the maximum duration for context operations before timing out.
	contextTimeout = 15 * time.Second
	// requestTimeout defines the maximum duration for request operations before timing out.
	requestTimeout = 20 * time.Second
)

// Config defines the configuration for the blocklist.
type Config struct {

	// Limit specifies the maximum number of items to process or validate.
	Limit uint

	// Validator specifies the IP validator to use.
	Validator parser.IPValidator

	// ContextTimeout defines the maximum duration for context operations before timing out.
	ContextTimeout time.Duration

	// RequestTimeout defines the maximum duration for request operations before timing out.
	RequestTimeout time.Duration
}

// NewConfig creates a new Config with default values.
func NewConfig(limit uint) Config {
	return Config{
		Limit:          limit,
		Validator:      &parser.DefaultIPValidator{},
		ContextTimeout: contextTimeout,
		RequestTimeout: requestTimeout,
	}
}

// NewConfigWithValidator creates a new Config with the specified validator.
func NewConfigWithValidator(limit uint, validator parser.IPValidator) Config {
	return Config{
		Limit:          limit,
		Validator:      validator,
		ContextTimeout: contextTimeout,
		RequestTimeout: requestTimeout,
	}
}

// Get fetches data from the given URL, parses the response using the provided parser, and applies the given configuration.
// It returns the parsed IPs and any errors that occurred during the process.
func Get(fileUrl string, parser parser.Parser, c Config) (parser.IPs, error) {
	parsedURL, err := url.Parse(fileUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme: %s", parsedURL.Scheme)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.ContextTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{
		Timeout: c.RequestTimeout,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	return parser.Parse(res.Body, c.Validator, c.Limit)
}
