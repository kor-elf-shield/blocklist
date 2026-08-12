package parser

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// ExclusionChecker is an interface for checking if an IP is excluded.
type ExclusionChecker interface {
	IsExcluded(ip string) (excluded bool, ips []string, err error)
}

type ipRange struct {
	start netip.Addr
	end   netip.Addr
	isV4  bool
}

type exclusionChecker struct {
	ipRanges []ipRange
}

// NewExclusionChecker creates a new exclusion checker.
func NewExclusionChecker(ips []string) (ExclusionChecker, error) {
	ipRanges := make([]ipRange, 0, len(ips))

	for _, ip := range ips {
		ipRange, err := parseSpec(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid exclusion IP: %s", ip)
		}

		ipRanges = append(ipRanges, ipRange)
	}

	return &exclusionChecker{
		ipRanges: ipRanges,
	}, nil
}

// IsExcluded checks if the given IP is excluded.
func (e *exclusionChecker) IsExcluded(ip string) (excluded bool, ips []string, err error) {
	inIPRange, err := parseSpec(ip)
	if err != nil {
		return false, nil, err
	}

	pending := []ipRange{inIPRange}
	matchedAny := false

	for _, baseRange := range e.ipRanges {
		// Different IP families do not overlap.
		if baseRange.isV4 != inIPRange.isV4 {
			continue
		}

		nextPending := make([]ipRange, 0, len(pending))
		for _, candidate := range pending {
			matched, remains := subtractRange(candidate, baseRange)
			if matched {
				matchedAny = true
			}
			nextPending = append(nextPending, remains...)
		}

		pending = nextPending
		if len(pending) == 0 {
			// Completely excluded the range.
			return true, []string{}, nil
		}
	}

	if !matchedAny {
		return false, nil, nil
	}

	out := make([]string, 0, len(pending))
	for _, r := range pending {
		out = append(out, formatRange(r))
	}
	return true, out, nil
}

func parseSpec(s string) (ipRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ipRange{}, fmt.Errorf("empty value")
	}

	// range: a-b
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return ipRange{}, fmt.Errorf("invalid range format")
		}
		a, err := parseAddr(strings.TrimSpace(parts[0]))
		if err != nil {
			return ipRange{}, err
		}
		b, err := parseAddr(strings.TrimSpace(parts[1]))
		if err != nil {
			return ipRange{}, err
		}
		if a.Is4() != b.Is4() {
			return ipRange{}, fmt.Errorf("mixed ip families in range")
		}
		if compareAddr(a, b) > 0 {
			return ipRange{}, fmt.Errorf("range start > end")
		}
		return ipRange{start: a, end: b, isV4: a.Is4()}, nil
	}

	// cidr
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return ipRange{}, fmt.Errorf("invalid cidr: %w", err)
		}
		p = p.Masked()
		start := p.Addr()

		var end netip.Addr
		if start.Is4() {
			u := ip4ToU32(start)
			hostBits := uint32(32 - p.Bits())
			var mask uint32
			if hostBits == 32 {
				mask = ^uint32(0)
			} else {
				mask = (uint32(1) << hostBits) - 1
			}
			end = u32ToIP4(u | mask)
			return ipRange{start: start, end: end, isV4: true}, nil
		}

		u := ip16ToBig(start)
		hostBits := 128 - p.Bits()
		ones := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))
		ones.Sub(ones, big.NewInt(1))
		u.Or(u, ones)
		end = bigToIP16(u)
		return ipRange{start: start, end: end, isV4: false}, nil
	}

	// single ip
	a, err := parseAddr(s)
	if err != nil {
		return ipRange{}, err
	}
	return ipRange{start: a, end: a, isV4: a.Is4()}, nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ip: %w", err)
	}
	return a.Unmap(), nil // important for ::ffff:1.2.3.4
}

func compareAddr(a, b netip.Addr) int {
	if a.Is4() && b.Is4() {
		ua := ip4ToU32(a)
		ub := ip4ToU32(b)
		switch {
		case ua < ub:
			return -1
		case ua > ub:
			return 1
		default:
			return 0
		}
	}
	aa := a.As16()
	bb := b.As16()
	for i := 0; i < 16; i++ {
		if aa[i] < bb[i] {
			return -1
		}
		if aa[i] > bb[i] {
			return 1
		}
	}
	return 0
}

func ip4ToU32(a netip.Addr) uint32 {
	v := a.As4()
	return binary.BigEndian.Uint32(v[:])
}

func u32ToIP4(u uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], u)
	return netip.AddrFrom4(b)
}

func ip16ToBig(a netip.Addr) *big.Int {
	v := a.As16()
	return new(big.Int).SetBytes(v[:])
}

func bigToIP16(x *big.Int) netip.Addr {
	var b [16]byte
	raw := x.Bytes()
	copy(b[16-len(raw):], raw)
	return netip.AddrFrom16(b)
}

func subtractRange(incoming, base ipRange) (bool, []ipRange) {
	// No intersection
	if compareAddr(base.end, incoming.start) < 0 || compareAddr(base.start, incoming.end) > 0 {
		return false, []ipRange{incoming}
	}

	// Full incoming coverage
	if compareAddr(base.start, incoming.start) <= 0 && compareAddr(base.end, incoming.end) >= 0 {
		return true, nil
	}

	remains := make([]ipRange, 0, 2)

	// Left side
	if compareAddr(base.start, incoming.start) > 0 {
		leftEnd, ok := prevIP(base.start)
		if ok && compareAddr(incoming.start, leftEnd) <= 0 {
			remains = append(remains, ipRange{
				start: incoming.start,
				end:   leftEnd,
				isV4:  incoming.isV4,
			})
		}
	}

	// Right side
	if compareAddr(base.end, incoming.end) < 0 {
		rightStart, ok := nextIP(base.end)
		if ok && compareAddr(rightStart, incoming.end) <= 0 {
			remains = append(remains, ipRange{
				start: rightStart,
				end:   incoming.end,
				isV4:  incoming.isV4,
			})
		}
	}

	return true, remains
}

func nextIP(a netip.Addr) (netip.Addr, bool) {
	if a.Is4() {
		u := ip4ToU32(a)
		if u == ^uint32(0) {
			return netip.Addr{}, false
		}
		return u32ToIP4(u + 1), true
	}

	u := ip16ToBig(a)
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	max.Sub(max, big.NewInt(1))
	if u.Cmp(max) == 0 {
		return netip.Addr{}, false
	}
	u.Add(u, big.NewInt(1))
	return bigToIP16(u), true
}

func prevIP(a netip.Addr) (netip.Addr, bool) {
	if a.Is4() {
		u := ip4ToU32(a)
		if u == 0 {
			return netip.Addr{}, false
		}
		return u32ToIP4(u - 1), true
	}

	u := ip16ToBig(a)
	if u.Sign() == 0 {
		return netip.Addr{}, false
	}
	u.Sub(u, big.NewInt(1))
	return bigToIP16(u), true
}

func formatRange(r ipRange) string {
	if r.start == r.end {
		return r.start.String()
	}
	return r.start.String() + "-" + r.end.String()
}
