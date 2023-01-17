package dnsforward

import (
	"math"
	"net"
	"net/netip"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// checkDNS64 checks if DNS64 should be performed.  It returns a DNS64 request
// for exchanging or nil if DNS64 is not desired.  Both req and resp must not be
// nil.  It also filters resp to not contain any NAT64 excluded addresses in the
// answer section, if needed.
//
// See https://datatracker.ietf.org/doc/html/rfc6147.
//
// TODO(e.burkov):  !! deal with timeouts ?
func (s *Server) checkDNS64(req, resp *dns.Msg) (dns64Req *dns.Msg) {
	if len(s.dns64Prefs) == 0 {
		return nil
	}

	q := req.Question[0]
	if q.Qtype != dns.TypeAAAA || q.Qclass != dns.ClassINET {
		// DNS64 operation for classes other than IN is undefined, and a DNS64
		// MUST behave as though no DNS64 function is configured.
		return nil
	}

	rcode := resp.Rcode
	if rcode == dns.RcodeNameError {
		// A result with RCODE=3 (Name Error) is handled according to normal DNS
		// operation (which is normally to return the error to the client).
		return nil
	}

	if rcode == dns.RcodeSuccess {
		// If resolver receives an answer with at least one AAAA record
		// containing an address outside any of the excluded range(s), then it
		// by default SHOULD build an answer section for a response including
		// only the AAAA record(s) that do not contain any of the addresses
		// inside the excluded ranges.
		if answers, hasAnswers := s.filterNAT64Answers(resp.Answer); hasAnswers {
			resp.Answer = answers

			return nil
		}

		// Any other RCODE is treated as though the RCODE were 0 and the answer
		// section were empty.
	}

	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                dns.Id(),
			RecursionDesired:  req.RecursionDesired,
			AuthenticatedData: req.AuthenticatedData,
			CheckingDisabled:  req.CheckingDisabled,
		},
		Question: []dns.Question{{
			Name:   req.Question[0].Name,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
}

// filterNAT64Answers filters out AAAA records that are within one of NAT64
// exclusion prefixes.  hasAnswers is true if the filtered slice contains at
// least a single AAAA answer not within the prefixes or a CNAME.
func (s *Server) filterNAT64Answers(rrs []dns.RR) (filtered []dns.RR, hasAnswers bool) {
	filtered = make([]dns.RR, 0, len(rrs))
	for _, ans := range rrs {
		switch ans := ans.(type) {
		case *dns.AAAA:
			addr, err := netutil.IPToAddrNoMapped(ans.AAAA)
			if err != nil {
				log.Error("dnsforward: bad AAAA record: %s", err)

				continue
			}

			if s.withinDNS64(addr) {
				// Filter the record.
				continue
			}

			filtered, hasAnswers = append(filtered, ans), true
		case *dns.CNAME:
			// If the response contains a CNAME or a DNAME, then the CNAME or
			// DNAME chain is followed until the first terminating A or AAAA
			// record is reached.
			//
			// Just treat CNAME responses as passable answers since AdGuard Home
			// doesn't follow any CNAME chains except the dnsrewrite-defined.
			filtered, hasAnswers = append(filtered, ans), true
		default:
			filtered = append(filtered, ans)
		}
	}

	if len(filtered) == len(rrs) {
		// No changes.
		filtered = rrs
	}

	return filtered, hasAnswers
}

// maxDNS64SynTTL is the maximum TTL for synthesized DNS64 responses in
// seconds.
//
// If the SOA RR was not delivered with the negative response to the AAAA query,
// then the DNS64 SHOULD use the TTL of the original A RR or 600 seconds,
// whichever is shorter.
//
// See https://datatracker.ietf.org/doc/html/rfc6147#section-5.1.7
const maxDNS64SynTTL uint32 = 600

// synthDNS64 synthesizes a DNS64 response using the original response as basis.
// It returns true if the response was actually synthesized.
func (s *Server) synthDNS64(origReq, origResp, resp *dns.Msg) (ok bool) {
	if len(resp.Answer) == 0 {
		// If there is an empty answer, then the DNS64 responds to the original
		// querying client with the answer the DNS64 received to the original
		// (initiator's) query.
		return false
	}

	// The Time to Live (TTL) field is set to the minimum of the TTL of the
	// original A RR and the SOA RR for the queried domain.
	//
	// Set initially to [math.MaxUint32], so that if there is no SOA record, the
	// TTL will still be set according to the rules.
	soaTTL := uint32(math.MaxUint32)
	for _, rr := range resp.Ns {
		if soa, isSOA := rr.(*dns.SOA); isSOA && soa.Hdr.Name == origReq.Question[0].Name {
			soaTTL = soa.Hdr.Ttl

			break
		}
	}

	newAns := make([]dns.RR, 0, len(resp.Answer))
	for _, ans := range resp.Answer {
		aResp, isA := ans.(*dns.A)
		if !isA {
			newAns = append(newAns, ans)

			continue
		}

		rr := s.synthAAAARR(aResp, soaTTL)
		if rr == nil {
			// The error should have already been logged.
			return false
		}

		newAns = append(newAns, rr)
	}

	origResp.Answer, origResp.Ns, origResp.Extra = newAns, resp.Ns, resp.Extra

	return true
}

const (
	// maxNAT64PrefixBitLen is the maximum length of a NAT64 prefix in bits.
	// See https://datatracker.ietf.org/doc/html/rfc6147#section-5.2.
	maxNAT64PrefixBitLen = 96

	// nat64PrefixLen is the length of a NAT64 prefix in bytes.
	nat64PrefixLen = maxNAT64PrefixBitLen / 8
)

// dns64WellKnownPref is the default prefix to use in an algorithmic mapping for
// DNS64.  See https://datatracker.ietf.org/doc/html/rfc6052#section-2.1.
var dns64WellKnownPref = netip.MustParsePrefix("64:ff9b::/96")

// withinDNS64 checks if ip is within one of the configured DNS64 prefixes.
func (s *Server) withinDNS64(ip netip.Addr) (ok bool) {
	return aghnet.SlicePrefixSet(s.dns64Prefs).Contains(ip)
}

// withinDNS64OrWellKnown checks if ip is within one of the configured DNS64
// prefixes or within a well-known prefix.  See [dns64WellKnownPref].
func (s *Server) withinDNS64OrWellKnown(ip netip.Addr) (ok bool) {
	return s.withinDNS64(ip) || dns64WellKnownPref.Contains(ip)
}

// mapDNS64 maps ip to IPv6 address using configured DNS64 prefix.  ip must be a
// valid IPv4.  It panics, if there are no configured DNS64 prefixes, because
// synthesis should not be performed unless DNS64 function enabled.
func (s *Server) mapDNS64(ip netip.Addr) (mapped netip.Addr) {
	// Don't mask the address here since it should have already been masked on
	// initialization stage.
	pref := s.dns64Prefs[0].Addr().As16()
	ipData := ip.As4()
	mappedData := *(*[net.IPv6len]byte)(append(pref[:nat64PrefixLen], ipData[:]...))

	return netip.AddrFrom16(mappedData)
}

// performDNS64 processes the current state of dctx assuming that it has already
// been tried to resolve, checks if it contains any acceptable response, and if
// it doesn't, performs DNS64 request and the following synthesis.  It returns
// the [resultCodeError] if there was an error set to dctx.
func (s *Server) performDNS64(prx *proxy.Proxy, dctx *dnsContext) (rc resultCode) {
	pctx := dctx.proxyCtx
	req := pctx.Req

	if dns64Req := s.checkDNS64(req, pctx.Res); dns64Req != nil {
		log.Debug("received an empty AAAA response, checking DNS64")

		var origReq, origResp *dns.Msg
		origReq, origResp, pctx.Req = pctx.Req, pctx.Res, dns64Req
		origUps := pctx.Upstream

		defer func() { pctx.Req = origReq }()

		if dctx.err = prx.Resolve(pctx); dctx.err != nil {
			return resultCodeError
		}

		var dns64Resp *dns.Msg
		dns64Resp, pctx.Res = pctx.Res, origResp
		if dns64Resp != nil && s.synthDNS64(origReq, pctx.Res, dns64Resp) {
			log.Debug("dnsforward: synthesized AAAA response for %q", origReq.Question[0].Name)
		} else {
			pctx.Upstream = origUps
		}
	}

	return resultCodeSuccess
}

// synthDNS64 synthesizes AAAA record for the current A response using the first
// configured DNS64 prefix and choosing the TTL of the resulting record
// according to the value of soaTTL.  If no SOA records contained in the
// original response, [math.MaxUint32] should be used as soaTTL.  It returns nil
// and logs the error in case the one occurs.
func (s *Server) synthAAAARR(aResp *dns.A, soaTTL uint32) (aaaa dns.RR) {
	addr, err := netutil.IPToAddr(aResp.A, netutil.AddrFamilyIPv4)
	if err != nil {
		log.Error("dnsforward: bad A record: %s", err)

		return nil
	}

	// Don't mask the address here since it should have already been masked on
	// initialization stage.
	pref := s.dns64Prefs[0].Addr().As16()
	ipData := addr.As4()

	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   aResp.Hdr.Name,
			Rrtype: dns.TypeAAAA,
			Class:  aResp.Hdr.Class,
		},
		AAAA: append(pref[:nat64PrefixLen], ipData[:]...),
	}

	switch rrTTL := aResp.Hdr.Ttl; {
	case rrTTL > soaTTL:
		rr.Hdr.Ttl = soaTTL
	case rrTTL > maxDNS64SynTTL:
		rr.Hdr.Ttl = maxDNS64SynTTL
	default:
		rr.Hdr.Ttl = rrTTL
	}

	return rr
}
