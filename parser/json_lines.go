package parser

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

type jsonLinesExtract func(item json.RawMessage) (string, error)

type jsonLinesParser struct {
	extract jsonLinesExtract
}

func NewJsonLines(extract jsonLinesExtract) (Parser, error) {
	if extract == nil {
		return nil, fmt.Errorf("json lines extract is nil")
	}

	return &jsonLinesParser{
		extract: extract,
	}, nil
}

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
