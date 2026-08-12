package blocklist

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"git.kor-elf.net/kor-elf-shield/blocklist/parser"
)

const (
	// contextTimeout defines the maximum duration for context operations before timing out.
	contextTimeout = 15 * time.Second

	// requestTimeout defines the maximum duration for request operations before timing out.
	requestTimeout = 20 * time.Second

	// maxDownloadSize defines the maximum allowed size of the downloaded file in bytes.
	maxDownloadSize int64 = 20 << 20 // 20 MiB

	// maxArchiveFileSize defines the maximum allowed size of the extracted file from ZIP in bytes.
	maxArchiveFileSize uint64 = 50 << 20 // 50 MiB
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

type ConfigZip struct {
	// Config is the configuration for the blocklist.
	Config Config

	// MaxDownloadSize defines the maximum allowed size of the downloaded file in bytes.
	MaxDownloadSize int64

	// MaxArchiveFileSize defines the maximum allowed size of the extracted file from ZIP in bytes.
	MaxArchiveFileSize uint64
}

// NewConfig creates a new Config with default values.
// limit is the maximum number of items to process or validate. 0 means no limit.
func NewConfig(limit uint) Config {
	return Config{
		Limit:          limit,
		Validator:      &parser.DefaultIPValidator{},
		ContextTimeout: contextTimeout,
		RequestTimeout: requestTimeout,
	}
}

func NewConfigWithExclusionChecker(limit uint, exclusionChecker parser.ExclusionChecker) Config {
	return Config{
		Limit: limit,
		Validator: &parser.DefaultIPValidator{
			ExclusionChecker: exclusionChecker,
		},
		ContextTimeout: contextTimeout,
		RequestTimeout: requestTimeout,
	}
}

// NewConfigWithValidator creates a new Config with the specified validator.
// limit is the maximum number of items to process or validate. 0 means no limit.
// validator is the IP validator to use.
func NewConfigWithValidator(limit uint, validator parser.IPValidator) Config {
	return Config{
		Limit:          limit,
		Validator:      validator,
		ContextTimeout: contextTimeout,
		RequestTimeout: requestTimeout,
	}
}

func NewConfigZip(c Config) ConfigZip {
	return ConfigZip{
		Config:             c,
		MaxDownloadSize:    maxDownloadSize,
		MaxArchiveFileSize: maxArchiveFileSize,
	}
}

// Get fetches data from the given URL, parses the response using the provided parser, and applies the given configuration.
// It returns the parsed IPs and any errors that occurred during the process.
func Get(fileUrl string, parser parser.Parser, c Config) (parser.IPs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.ContextTimeout)
	defer cancel()

	res, err := fetch(fileUrl, ctx, c.RequestTimeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	return parser.Parse(res.Body, c.Validator, c.Limit)
}

// GetSeparatedIPs fetches data from the given URL, parses the response using the provided parser, and applies the given configuration.
// It returns the parsed IPs and any errors that occurred during the process.
func GetSeparatedIPs(fileUrl string, parser parser.Parser, c Config) (ipV4 parser.IPs, ipV6 parser.IPs, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.ContextTimeout)
	defer cancel()

	res, err := fetch(fileUrl, ctx, c.RequestTimeout)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	return parser.ParseIPsByVersion(res.Body, c.Validator, c.Limit)
}

// GetZip fetches data from the given URL, parses the response using the provided parser, and applies the given configuration.
// It returns the parsed IPs and any errors that occurred during the process.
func GetZip(fileUrl string, parser parser.Parser, c ConfigZip) (parser.IPs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Config.ContextTimeout)
	defer cancel()

	res, err := fetch(fileUrl, ctx, c.Config.RequestTimeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	if c.MaxDownloadSize > 0 && res.ContentLength > c.MaxDownloadSize {
		return nil, fmt.Errorf("downloaded file is too large: content-length %d exceeds limit %d", res.ContentLength, c.MaxDownloadSize)
	}

	reader := res.Body
	if c.MaxDownloadSize > 0 {
		reader = io.NopCloser(io.LimitReader(res.Body, c.MaxDownloadSize+1))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if c.MaxDownloadSize > 0 && int64(len(body)) > c.MaxDownloadSize {
		return nil, fmt.Errorf("downloaded file exceeds limit %d bytes", c.MaxDownloadSize)
	}

	if !isZip(body) {
		return nil, fmt.Errorf("invalid zip archive")
	}

	return parseZip(body, parser, c)
}

// GetZipSeparatedIPs fetches data from the given URL, parses the response using the provided parser, and applies the given configuration.
// It returns the parsed IPs and any errors that occurred during the process.
func GetZipSeparatedIPs(fileUrl string, parser parser.Parser, c ConfigZip) (ipV4 parser.IPs, ipV6 parser.IPs, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Config.ContextTimeout)
	defer cancel()

	res, err := fetch(fileUrl, ctx, c.Config.RequestTimeout)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	if c.MaxDownloadSize > 0 && res.ContentLength > c.MaxDownloadSize {
		return nil, nil, fmt.Errorf("downloaded file is too large: content-length %d exceeds limit %d", res.ContentLength, c.MaxDownloadSize)
	}

	reader := res.Body
	if c.MaxDownloadSize > 0 {
		reader = io.NopCloser(io.LimitReader(res.Body, c.MaxDownloadSize+1))
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read response body: %w", err)
	}

	if c.MaxDownloadSize > 0 && int64(len(body)) > c.MaxDownloadSize {
		return nil, nil, fmt.Errorf("downloaded file exceeds limit %d bytes", c.MaxDownloadSize)
	}

	if !isZip(body) {
		return nil, nil, fmt.Errorf("invalid zip archive")
	}

	return parseZipSeparatedIPs(body, parser, c)
}

func isZip(body []byte) bool {
	return len(body) >= 4 &&
		body[0] == 'P' &&
		body[1] == 'K' &&
		body[2] == 0x03 &&
		body[3] == 0x04
}

func parseZip(body []byte, p parser.Parser, c ConfigZip) (parser.IPs, error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open zip archive: %w", err)
	}

	file := findArchiveFile(reader.File)
	if file == nil {
		return nil, fmt.Errorf("zip archive does not contain a supported file")
	}

	if c.MaxArchiveFileSize > 0 && file.UncompressedSize64 > c.MaxArchiveFileSize {
		return nil, fmt.Errorf("file %q in zip is too large: %d exceeds limit %d", file.Name, file.UncompressedSize64, c.MaxArchiveFileSize)
	}

	rc, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open file %q from zip: %w", file.Name, err)
	}
	defer func() {
		_ = rc.Close()
	}()

	var zipReader io.Reader = rc
	if c.MaxArchiveFileSize > 0 {
		zipReader = io.LimitReader(rc, int64(c.MaxArchiveFileSize)+1)
	}

	return p.Parse(zipReader, c.Config.Validator, c.Config.Limit)
}

func parseZipSeparatedIPs(body []byte, p parser.Parser, c ConfigZip) (ipV4 parser.IPs, ipV6 parser.IPs, err error) {
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, nil, fmt.Errorf("open zip archive: %w", err)
	}

	file := findArchiveFile(reader.File)
	if file == nil {
		return nil, nil, fmt.Errorf("zip archive does not contain a supported file")
	}

	if c.MaxArchiveFileSize > 0 && file.UncompressedSize64 > c.MaxArchiveFileSize {
		return nil, nil, fmt.Errorf("file %q in zip is too large: %d exceeds limit %d", file.Name, file.UncompressedSize64, c.MaxArchiveFileSize)
	}

	rc, err := file.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("open file %q from zip: %w", file.Name, err)
	}
	defer func() {
		_ = rc.Close()
	}()

	var zipReader io.Reader = rc
	if c.MaxArchiveFileSize > 0 {
		zipReader = io.LimitReader(rc, int64(c.MaxArchiveFileSize)+1)
	}

	return p.ParseIPsByVersion(zipReader, c.Config.Validator, c.Config.Limit)
}

func findArchiveFile(files []*zip.File) *zip.File {
	var fallback *zip.File

	for _, file := range files {
		if file.FileInfo().IsDir() {
			continue
		}

		if fallback == nil {
			fallback = file
		}

		name := strings.ToLower(file.Name)
		if strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".json") ||
			strings.HasSuffix(name, ".xml") ||
			strings.HasSuffix(name, ".rss") {
			return file
		}
	}

	return fallback
}

func fetch(fileUrl string, ctx context.Context, requestTimeout time.Duration) (*http.Response, error) {
	parsedURL, err := url.Parse(fileUrl)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid url scheme: %s", parsedURL.Scheme)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{
		Timeout: requestTimeout,
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	return res, nil
}
