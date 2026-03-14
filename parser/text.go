package parser

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// TextExtract defines the function signature for extracting IP addresses from a text item.
type TextExtract interface {
	// Extract extracts an IP address from the given text line.
	Extract(line string) (string, bool)
}

// defaultTextExtract is a default implementation of TextExtract.
type defaultTextExtract struct {
	// fieldIndexOne is the index of the field that contains the IP address.
	fieldIndexOne uint8

	// separator is the separator used to split the fields.
	separator string
}

// Extract extracts an IP address from the given text line.
// It returns the IP address and a boolean indicating whether the IP address was found.
func (d *defaultTextExtract) Extract(line string) (string, bool) {
	fields := strings.Split(line, d.separator)
	if len(fields) <= int(d.fieldIndexOne) {
		return "", false
	}

	return fields[d.fieldIndexOne], true
}

// intervalTextExtract is a TextExtract implementation that extracts an IP address range from a text line.
type intervalTextExtract struct {
	// fieldIndexOne specifies the index of the first field to extract from the split string.
	// From this field, the IP address range will be extracted.
	fieldIndexOne uint8

	// fieldIndexTwo specifies the index of the second field to extract from the split string.
	// This field will be used as the end of the IP address range.
	fieldIndexTwo uint8

	// separator specifies the separator used to split the fields.
	separator string
}

// Extract extracts an IP address range from the given text line.
// It returns the IP address range and a boolean indicating whether the IP address range was found.
func (d *intervalTextExtract) Extract(line string) (string, bool) {
	fields := strings.Split(line, d.separator)
	if len(fields) <= int(d.fieldIndexOne) || len(fields) <= int(d.fieldIndexTwo) {
		return "", false
	}

	return fields[d.fieldIndexOne] + "-" + fields[d.fieldIndexTwo], true
}

// cidrTextExtract is a TextExtract implementation that extracts an IP address range from a text line.
type cidrTextExtract struct {
	// fieldIndexOne is the index of the field that contains the IP address.
	fieldIndexOne uint8

	// fieldIndexTwo is the index of the field that contains the CIDR prefix length.
	fieldIndexTwo uint8

	// separator is the separator used to split the fields.
	separator string
}

// Extract extracts an IP address range from the given text line.
// It returns the IP address range and a boolean indicating whether the IP address range was found.
func (d *cidrTextExtract) Extract(line string) (string, bool) {
	fields := strings.Split(line, d.separator)
	if len(fields) <= int(d.fieldIndexOne) || len(fields) <= int(d.fieldIndexTwo) {
		return "", false
	}
	return fields[d.fieldIndexOne] + "/" + fields[d.fieldIndexTwo], true
}

// NewDefaultTextExtract creates a new default TextExtract instance.
func NewDefaultTextExtract(fieldIndexOne uint8, separator string) TextExtract {
	return &defaultTextExtract{
		fieldIndexOne: fieldIndexOne,
		separator:     separator,
	}
}

// NewIntervalTextExtract creates a new TextExtract instance that extracts an IP address range.
func NewIntervalTextExtract(fieldIndexOne uint8, fieldIndexTwo uint8, separator string) TextExtract {
	return &intervalTextExtract{
		fieldIndexOne: fieldIndexOne,
		fieldIndexTwo: fieldIndexTwo,
		separator:     separator,
	}
}

// NewCIDRTextExtract creates a new TextExtract instance that extracts an IP address range.
func NewCIDRTextExtract(fieldIndexOne uint8, fieldIndexTwo uint8, separator string) TextExtract {
	return &cidrTextExtract{
		fieldIndexOne: fieldIndexOne,
		fieldIndexTwo: fieldIndexTwo,
		separator:     separator,
	}
}

// textParser is a parser implementation that reads text data from an io.Reader and extracts IP addresses.
type textParser struct {
	textExtract TextExtract
}

// NewText creates a new TextParser instance.
func NewText(textExtract TextExtract) (Parser, error) {
	if textExtract == nil || textExtract.Extract == nil {
		return nil, fmt.Errorf("text extract is nil")
	}

	return &textParser{
		textExtract: textExtract,
	}, nil
}

// Parse reads text data from the given io.Reader and extracts IP addresses.
func (p *textParser) Parse(body io.Reader, validator IPValidator, limit uint) (IPs, error) {
	scanner := bufio.NewScanner(body)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	var ips IPs
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		ip, isFound := p.textExtract.Extract(line)
		if !isFound {
			continue
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

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return ips, nil
}
