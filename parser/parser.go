package parser

import (
	"bytes"
	"io"
	"net"
	"strings"
)

// Parser interface defines the contract for parsing IP addresses from a given reader.
type Parser interface {
	// Parse reads the body and returns a slice of IP addresses.
	Parse(body io.Reader, validator IPValidator, limit uint) (IPs, error)

	ParseIPsByVersion(body io.Reader, validator IPValidator, limit uint) (ipV4 IPs, ipV6 IPs, err error)
}

// IPValidator interface defines the contract for validating IP addresses.
type IPValidator interface {
	// IsValid checks if the given IP address is valid.
	IsValid(ip string) bool

	// IsValidAndReturnVersion validates the given IP address and returns whether it is valid and its version (IPv4 or IPv6).
	IsValidAndReturnVersion(ip string) (bool, IPVersion)

	// IsExcluded determines if the given IP address is excluded based on certain criteria and returns related IP addresses.
	IsExcluded(ip string) (excluded bool, ips []string, err error)
}

type IPVersion int

const (
	IPVersion4 IPVersion = iota
	IPVersion6
)

// IPs is a slice of IP addresses.
type IPs []string

// DefaultIPValidator implements IPValidator interface.
// It validates IP addresses by parsing them using net.ParseIP and net.ParseCIDR.
type DefaultIPValidator struct {
	ExclusionChecker ExclusionChecker
}

// IsValid checks if the given IP address is valid.
// It returns true if the IP address is not a loopback address.
func (v *DefaultIPValidator) IsValid(value string) bool {
	if value == "" {
		return false
	}

	if ip := net.ParseIP(value); ip != nil {
		if ip.IsLoopback() {
			return false
		}
		return true
	}

	if ip, _, err := net.ParseCIDR(value); err == nil {
		if ip.IsLoopback() {
			return false
		}
		return true
	}

	return false
}

// IsValidAndReturnVersion checks if the given IP address is valid and returns the IP version.
// It returns true if the IP address is not a loopback address and the IP version is either IPv4 or IPv6.
func (v *DefaultIPValidator) IsValidAndReturnVersion(value string) (bool, IPVersion) {
	if value == "" {
		return false, IPVersion4
	}

	if ip := net.ParseIP(value); ip != nil {
		if ip.IsLoopback() {
			return false, IPVersion4
		}

		if ip.To4() != nil {
			return true, IPVersion4
		}

		if ip.To16() != nil {
			return true, IPVersion6
		}

		return false, IPVersion4
	}

	if ip, _, err := net.ParseCIDR(value); err == nil {
		if ip.IsLoopback() {
			return false, IPVersion4
		}

		if ip.To4() != nil {
			return true, IPVersion4
		}

		if ip.To16() != nil {
			return true, IPVersion6
		}

		return false, IPVersion4
	}

	return false, IPVersion4
}

func (v *DefaultIPValidator) IsExcluded(ip string) (excluded bool, ips []string, err error) {
	if v.ExclusionChecker == nil {
		return false, nil, nil
	}
	return v.ExclusionChecker.IsExcluded(ip)
}

// IPRangeValidator implements IPValidator interface.
// It validates IP ranges by parsing them using net.ParseIP and checking if the start and end IPs are in the same network.
type IPRangeValidator struct {
	ExclusionChecker ExclusionChecker
}

// IsValid checks if the given IP range is valid.
// It returns true if the start and end IPs are in the same network.
func (v *IPRangeValidator) IsValid(value string) bool {
	if value == "" {
		return false
	}

	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false
	}

	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return false
	}

	start4 := start.To4()
	end4 := end.To4()

	switch {
	case start4 != nil && end4 != nil:
		return bytes.Compare(start4, end4) <= 0
	case start4 == nil && end4 == nil:
		start16 := start.To16()
		end16 := end.To16()
		if start16 == nil || end16 == nil {
			return false
		}
		return bytes.Compare(start16, end16) <= 0
	default:
		return false
	}
}

func (v *IPRangeValidator) IsValidAndReturnVersion(value string) (bool, IPVersion) {
	if value == "" {
		return false, IPVersion4
	}

	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false, IPVersion4
	}

	start := net.ParseIP(strings.TrimSpace(parts[0]))
	end := net.ParseIP(strings.TrimSpace(parts[1]))
	if start == nil || end == nil {
		return false, IPVersion4
	}

	start4 := start.To4()
	end4 := end.To4()

	switch {
	case start4 != nil && end4 != nil:
		if bytes.Compare(start4, end4) <= 0 {
			return true, IPVersion4
		}
		return false, IPVersion4
	case start4 == nil && end4 == nil:
		start16 := start.To16()
		end16 := end.To16()
		if start16 == nil || end16 == nil {
			return false, IPVersion4
		}
		if bytes.Compare(start16, end16) <= 0 {
			return true, IPVersion6
		}
		return false, IPVersion4
	default:
		return false, IPVersion4
	}
}

func (v *IPRangeValidator) IsExcluded(ip string) (excluded bool, ips []string, err error) {
	if v.ExclusionChecker == nil {
		return false, nil, nil
	}
	return v.ExclusionChecker.IsExcluded(ip)
}
