package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// rssExtract defines the function signature for extracting IP addresses from a RSS item.
type rssExtract func(decoder *xml.Decoder, start xml.StartElement) (string, error)

// rssParser is a parser for RSS data.
type rssParser struct {
	// extract is the function that extracts an IP address from a RSS item.
	extract rssExtract
}

// NewRss creates a new RSS parser.
func NewRss(extract rssExtract) (Parser, error) {
	if extract == nil {
		return nil, fmt.Errorf("rss extract is nil")
	}

	return &rssParser{
		extract: extract,
	}, nil
}

// Parse parses the RSS data from the given reader.
// It returns a slice of IP addresses and any errors that occurred during the process.
func (p *rssParser) Parse(body io.Reader, validator IPValidator, limit uint) (IPs, error) {
	decoder := xml.NewDecoder(body)
	ips := make(IPs, 0)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, fmt.Errorf("parse rss: %w", err)
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		ip, err := p.extract(decoder, start)
		if err != nil {
			return nil, fmt.Errorf("extract rss ip: %w", err)
		}

		ip = strings.TrimSpace(ip)
		if !validator.IsValid(ip) {
			continue
		}

		ips, err = appendIfNotExcluded(ip, ips, validator)
		if err != nil {
			return nil, err
		}
		if limit > 0 && uint(len(ips)) >= limit {
			break
		}
	}

	return ips, nil
}

// ParseIPsByVersion parses the RSS data from the given reader
// and returns a slice of IP addresses for each IP version.
// It also returns any errors that occurred during the process.
func (p *rssParser) ParseIPsByVersion(body io.Reader, validator IPValidator, limit uint) (ipV4 IPs, ipV6 IPs, err error) {
	decoder := xml.NewDecoder(body)
	ipV4 = make(IPs, 0)
	ipV6 = make(IPs, 0)

	for {
		token, err := decoder.Token()
		if err != nil {
			if err == io.EOF {
				break
			}

			return nil, nil, fmt.Errorf("parse rss: %w", err)
		}

		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		ip, err := p.extract(decoder, start)
		if err != nil {
			return nil, nil, fmt.Errorf("extract rss ip: %w", err)
		}

		ip = strings.TrimSpace(ip)
		isValid, ipVersion := validator.IsValidAndReturnVersion(ip)
		if !isValid {
			continue
		}

		if ipVersion == IPVersion4 {
			ipV4, err = appendIfNotExcluded(ip, ipV4, validator)
			if err != nil {
				return nil, nil, err
			}
		} else if ipVersion == IPVersion6 {
			ipV6, err = appendIfNotExcluded(ip, ipV6, validator)
			if err != nil {
				return nil, nil, err
			}
		} else {
			continue
		}

		if limit > 0 && uint(len(ipV4))+uint(len(ipV6)) >= limit {
			break
		}
	}

	return ipV4, ipV6, nil
}
