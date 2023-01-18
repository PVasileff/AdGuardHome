package dnsforward

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghtest"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// newRR is a helper that creates a new dns.RR with the given name, qtype, ttl
// and value.  It fails the test if the qtype is not supported or the type of
// value doesn't match the qtype.
func newRR(t *testing.T, name string, qtype uint16, ttl uint32, val any) (rr dns.RR) {
	t.Helper()

	switch qtype {
	case dns.TypeA:
		require.IsType(t, net.IP{}, val)

		rr = &dns.A{A: val.(net.IP)}
	case dns.TypeAAAA:
		require.IsType(t, net.IP{}, val)

		rr = &dns.AAAA{AAAA: val.(net.IP)}
	case dns.TypeCNAME:
		require.IsType(t, "", val)

		rr = &dns.CNAME{Target: val.(string)}
	case dns.TypeSOA:
		rr = &dns.SOA{
			Ns:      "ns." + name,
			Mbox:    "hostmaster." + name,
			Serial:  1,
			Refresh: 1,
			Retry:   1,
			Expire:  1,
			Minttl:  1,
		}
	case dns.TypePTR:
		require.IsType(t, "", val)

		rr = &dns.PTR{Ptr: val.(string)}
	default:
		t.Fatalf("unsupported qtype: %d", qtype)
	}

	hdr := rr.Header()
	hdr.Name = name
	hdr.Rrtype = qtype
	hdr.Class = dns.ClassINET
	hdr.Ttl = ttl

	return rr
}

func TestServer_Server_dns64(t *testing.T) {
	const (
		sectionAnswer = iota
		sectionAuthority
		sectionAdditional
	)

	// nameType is a convenience alias for question's name and type pair.
	type nameType = struct {
		string
		uint16
	}

	newUpstream := func(answers map[nameType][3][]dns.RR) upstream.Upstream {
		pt := testutil.PanicT{}

		return aghtest.NewUpstreamMock(func(req *dns.Msg) (resp *dns.Msg, err error) {
			q := req.Question[0]

			resp = (&dns.Msg{}).SetReply(req)
			answer, ok := answers[nameType{q.Name, q.Qtype}]
			require.Truef(pt, ok, "request: %v", q)

			resp.Answer = answer[sectionAnswer]
			resp.Ns = answer[sectionAuthority]
			resp.Extra = answer[sectionAdditional]

			return resp, nil
		})
	}

	const (
		ipv4Domain    = "ipv4.only."
		ipv6Domain    = "ipv6.only."
		soaDomain     = "ipv4.soa."
		mappedDomain  = "filterable.ipv6."
		anotherDomain = "another.domain."

		ptr64Domain   = "4.0.3.0.2.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa."
		pointedDomain = "real1234.ipv4."
		ptrGlobDomain = "4.0.3.0.2.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
		globDomain    = "real1234.ipv4."
	)

	someIPv4 := net.IP{1, 2, 3, 4}
	someIPv6 := net.IP{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	mappedIPv6 := net.ParseIP("64:ff9b::102:304")

	answers := map[nameType][3][]dns.RR{
		{ipv4Domain, dns.TypeA}: {
			sectionAnswer: {newRR(t, ipv4Domain, dns.TypeA, 3600, someIPv4)},
		},
		{ipv4Domain, dns.TypeAAAA}: {},
		{ipv6Domain, dns.TypeA}:    {},
		{ipv6Domain, dns.TypeAAAA}: {
			sectionAnswer: {newRR(t, ipv6Domain, dns.TypeAAAA, 3600, someIPv6)},
		},
		{soaDomain, dns.TypeA}: {
			sectionAnswer: {newRR(t, soaDomain, dns.TypeA, 3600, someIPv4)},
		},
		{soaDomain, dns.TypeAAAA}: {
			sectionAuthority: {newRR(t, soaDomain, dns.TypeSOA, maxDNS64SynTTL+50, nil)},
		},
		{mappedDomain, dns.TypeAAAA}: {
			sectionAnswer: {
				newRR(t, mappedDomain, dns.TypeAAAA, 3600, net.ParseIP("64:ff9b::506:708")),
				newRR(t, mappedDomain, dns.TypeCNAME, 3600, anotherDomain),
			},
		},
		{mappedDomain, dns.TypeA}: {},
		{ptrGlobDomain, dns.TypePTR}: {
			sectionAnswer: {newRR(t, ptrGlobDomain, dns.TypePTR, 3600, globDomain)},
		},
	}
	localAnswers := map[nameType][3][]dns.RR{
		{ptr64Domain, dns.TypePTR}: {
			sectionAnswer: {newRR(t, ptr64Domain, dns.TypePTR, 3600, pointedDomain)},
		},
	}

	s := createTestServer(t, &filtering.Config{}, ServerConfig{
		UDPListenAddrs: []*net.UDPAddr{{}},
		TCPListenAddrs: []*net.TCPAddr{{}},
		UseDNS64:       true,
	}, newUpstream(localAnswers))
	s.conf.UpstreamConfig.Upstreams = []upstream.Upstream{newUpstream(answers)}
	startDeferStop(t, s)

	addrStr := s.dnsProxy.Addr(proxy.ProtoUDP).String()

	testCases := []struct {
		name    string
		qname   string
		wantAns []dns.RR
		qtype   uint16
	}{{
		name:  "simple_a",
		qname: ipv4Domain,
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:     ipv4Domain,
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 4,
			},
			A: someIPv4,
		}},
		qtype: dns.TypeA,
	}, {
		name:  "simple_aaaa",
		qname: ipv6Domain,
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     ipv6Domain,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 16,
			},
			AAAA: someIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "actual_dns64",
		qname: ipv4Domain,
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     ipv4Domain,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      maxDNS64SynTTL,
				Rdlength: 16,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "actual_dns64_soattl",
		qname: soaDomain,
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     soaDomain,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      maxDNS64SynTTL + 50,
				Rdlength: 16,
			},
			AAAA: mappedIPv6,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "filtered",
		qname: mappedDomain,
		wantAns: []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:     mappedDomain,
				Rrtype:   dns.TypeCNAME,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 16,
			},
			Target: anotherDomain,
		}},
		qtype: dns.TypeAAAA,
	}, {
		name:  "ptr",
		qname: ptr64Domain,
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:     ptr64Domain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 15,
			},
			Ptr: pointedDomain,
		}},
		qtype: dns.TypePTR,
	}, {
		name:  "ptr_glob",
		qname: ptrGlobDomain,
		wantAns: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:     ptrGlobDomain,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      3600,
				Rdlength: 15,
			},
			Ptr: globDomain,
		}},
		qtype: dns.TypePTR,
	}}

	client := &dns.Client{
		Net:     "udp",
		Timeout: 5 * time.Second,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := (&dns.Msg{}).SetQuestion(tc.qname, tc.qtype)

			resp, _, err := client.Exchange(req, addrStr)
			require.NoError(t, err)

			require.Equal(t, tc.wantAns, resp.Answer)
		})
	}
}
