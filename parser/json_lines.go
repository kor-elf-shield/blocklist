package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// jsonLinesExtract defines the function signature for extracting IP addresses from a JSON Lines item.
type jsonLinesExtract func(item json.RawMessage) (string, error)

// jsonLinesParser is a parser for JSON Lines data.
type jsonLinesParser struct {
	// extract is the function that extracts an IP address from a JSON Lines item.
	extract jsonLinesExtract
}

// NewJsonLines creates a new JSON Lines parser.
func NewJsonLines(extract jsonLinesExtract) (Parser, error) {
	if extract == nil {
		return nil, fmt.Errorf("json lines extract is nil")
	}

	return &jsonLinesParser{
		extract: extract,
	}, nil
}

// Parse parses the JSON Lines data from the given reader.
// It returns a slice of IP addresses and any errors that occurred during the process.
func (p *jsonLinesParser) Parse(body io.Reader, validator IPValidator, limit uint) (IPs, error) {
	decoder := json.NewDecoder(body)
	ips := make(IPs, 0)
	for {
		var item json.RawMessage
		if err := decoder.Decode(&item); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode json item: %w", err)
		}

		if item == nil {
			continue
		}

		ip, err := p.extract(item)
		if err != nil {
			return nil, fmt.Errorf("extract ip: %w", err)
		}

		ip = strings.TrimSpace(ip)
		if !validator.IsValid(ip) {
			continue
		}

		ips = append(ips, ip)
		if limit > 0 && uint(len(ips)) >= limit {
			break
		}
	}

	return ips, nil
}
