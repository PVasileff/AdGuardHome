package aghnet

import (
	"net/netip"
)

// PrefixSet is a set of prefixes.
//
// TODO(e.burkov):  Put into golibs.
type PrefixSet interface {
	// Contains returns true if ip is within at least a single prefix in the
	// set.
	Contains(ip netip.Addr) (ok bool)
}

// SlicePrefixSet is the [PrefixSet] implementation that checks an address
// through a slice of [netip.Prefix].
type SlicePrefixSet []netip.Prefix

// type check
var _ PrefixSet = (SlicePrefixSet)(nil)

// Contains implements the [PrefixSet] interface for [SlicePrefixSet].
func (s SlicePrefixSet) Contains(ip netip.Addr) (ok bool) {
	for _, n := range s {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}
