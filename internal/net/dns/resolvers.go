// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	miekg "github.com/miekg/dns"
	"github.com/owasp-amass/resolve/conn"
	"github.com/owasp-amass/resolve/pool"
	"github.com/owasp-amass/resolve/servers"
	"github.com/owasp-amass/resolve/types"
	"github.com/owasp-amass/resolve/wildcards"
	"golang.org/x/time/rate"
)

// DefaultResolvers are the public DNS resolvers an enumeration queries when
// its configuration names none.
var DefaultResolvers = []string{
	"8.8.8.8",         // Google Primary
	"95.85.95.85",     // Gcore DNS Primary
	"2.56.220.2",      // Gcore DNS Secondary
	"76.76.2.0",       // ControlD Primary
	"76.76.10.0",      // ControlD Secondary
	"9.9.9.9",         // Quad9 Primary
	"149.112.112.112", // Quad9 Secondary
	"208.67.222.222",  // Cisco OpenDNS Home Primary
	"208.67.220.220",  // Cisco OpenDNS Home Secondary
	"1.1.1.1",         // Cloudflare Primary
	"1.0.0.1",         // Cloudflare Secondary
	"185.228.168.9",   // CleanBrowsing Primary
	"185.228.169.9",   // CleanBrowsing Secondary
	"76.76.19.19",     // Alternate DNS Primary
	"76.223.122.150",  // Alternate DNS Secondary
	"94.140.14.14",    // AdGuard DNS Primary
	"94.140.15.15",    // AdGuard DNS Secondary
	"176.103.130.130", // AdGuard
	"176.103.130.131", // AdGuard
	"8.26.56.26",      // Comodo Secure DNS Primary
	"8.20.247.20",     // Comodo Secure DNS Secondary
	"205.171.3.65",    // CenturyLink Level3 Primary
	"205.171.2.65",    // CenturyLink Level3 Secondary
	"64.6.64.6",       // Verisign DNS Primary
	"64.6.65.6",       // Verisign DNS Secondary
	"209.244.0.3",     // CenturyLink Level3
	"209.244.0.4",     // CenturyLink Level3
	"149.112.121.10",  // CIRA Canadian Shield Primary
	"149.112.122.10",  // CIRA Canadian Shield Secondary
	"138.197.140.189", // OpenNIC Primary
	"162.243.19.47",   // OpenNIC Secondary
	"216.87.84.211",   // OpenNIC
	"23.90.4.6",       // OpenNIC
	"216.146.35.35",   // Oracle Dyn Primary
	"216.146.36.36",   // Oracle Dyn Secondary
	"91.239.100.100",  // UncensoredDNS Primary
	"89.233.43.71",    // UncensoredDNS Secondary
	"77.88.8.8",       // Yandex.DNS Primary
	"77.88.8.1",       // Yandex.DNS Secondary
	"74.82.42.42",     // Hurricane Electric Primary
	"94.130.180.225",  // DNS for Family Primary
	"78.47.64.161",    // DNS for Family Secondary
	"80.80.80.80",     // Freenom World Primary
	"80.80.81.81",     // Freenom World Secondary
	"84.200.69.80",    // DNS.WATCH Primary
	"84.200.70.40",    // DNS.WATCH Secondary
	"156.154.70.5",    // Neustar Primary
	"156.157.71.5",    // Neustar Secondary
	"81.218.119.11",   // GreenTeamDNS Primary
	"209.88.198.133",  // GreenTeamDNS Secondary
	"37.235.1.177",    // FreeDNS
	"38.132.106.139",  // CyberGhost
}

// DefaultWildcardResolver is the resolver that tests for DNS wildcards when
// the configuration names no trusted resolver. It is not in
// DefaultResolvers, so the wildcard tests do not compete with the queries.
const DefaultWildcardResolver = "8.8.4.4"

// DefaultResolverQPS is the number of queries per second the engine sends to
// any one resolver, across all its sessions, unless SetResolverQPS changes it.
const DefaultResolverQPS = 15

// queryTimeout is how long a query waits for its answer.
const queryTimeout = 250 * time.Millisecond

// Resolvers is a pool of DNS resolvers and the wildcard detector that goes
// with it. The resolvers themselves are shared by every pool in the engine,
// so the per-resolver rate limit holds across sessions.
type Resolvers struct {
	pool     *pool.Pool
	conns    *conn.Conn
	wconns   *conn.Conn
	detector *wildcards.Detector
	stop     sync.Once
}

// NewResolvers builds a pool that sends its queries to the query resolvers
// and tests for wildcards with the wildcard resolver. Without query
// resolvers it uses DefaultResolvers, and without a wildcard resolver
// DefaultWildcardResolver. A resolver is an IP address with an optional
// port; a host name is an error.
func NewResolvers(query []string, wildcard string) (*Resolvers, error) {
	if len(query) == 0 {
		query = DefaultResolvers
	}
	if strings.TrimSpace(wildcard) == "" {
		wildcard = DefaultWildcardResolver
	}

	var servs []types.Nameserver
	for _, addr := range query {
		s, err := shared.get(addr)
		if err != nil {
			return nil, err
		}
		servs = append(servs, s)
	}
	ws, err := shared.get(wildcard)
	if err != nil {
		return nil, err
	}

	cpus := runtime.NumCPU()
	sel := newRotation(servs...)
	conns := conn.New(cpus, sel)
	wconns := conn.New(cpus, newRotation(ws))
	return &Resolvers{
		pool:     pool.New(0, sel, conns, nil),
		conns:    conns,
		wconns:   wconns,
		detector: wildcards.NewDetector(ws, wconns, nil),
	}, nil
}

// NewSessionResolvers builds the pool for an enumeration's resolver
// settings: queries go to the untrusted resolvers when there are any, and
// otherwise to the trusted ones, and the first trusted resolver tests for
// wildcards. With neither, it returns nil, and the session uses Default.
func NewSessionResolvers(untrusted, trusted []string) (*Resolvers, error) {
	if len(untrusted) == 0 && len(trusted) == 0 {
		return nil, nil
	}

	query := untrusted
	if len(query) == 0 {
		query = trusted
	}
	var wildcard string
	if len(trusted) > 0 {
		wildcard = trusted[0]
	}
	return NewResolvers(query, wildcard)
}

// Exchange sends the query to a resolver in the pool and returns its answer.
func (r *Resolvers) Exchange(ctx context.Context, msg *miekg.Msg) (*miekg.Msg, error) {
	return r.pool.Exchange(ctx, msg)
}

// WildcardDetected reports whether the answer could come from a DNS wildcard
// in the registered domain.
func (r *Resolvers) WildcardDetected(ctx context.Context, resp *miekg.Msg, domain string) bool {
	return r.detector.WildcardDetected(ctx, resp, domain)
}

// Stop releases the pool's connections. Queries sent after Stop fail. The
// shared resolvers stay for the other pools.
func (r *Resolvers) Stop() {
	r.stop.Do(func() {
		r.pool.Stop()
		r.conns.Close()
		r.wconns.Close()
	})
}

var (
	defaultOnce      sync.Once
	defaultResolvers *Resolvers
)

// Default returns the engine's pool of DefaultResolvers, built on first use.
func Default() *Resolvers {
	defaultOnce.Do(func() {
		defaultResolvers, _ = NewResolvers(nil, "")
	})
	return defaultResolvers
}

type resolversKey struct{}

// WithResolvers returns a copy of ctx that carries the pool, so the queries
// made with that context go to its resolvers.
func WithResolvers(ctx context.Context, r *Resolvers) context.Context {
	return context.WithValue(ctx, resolversKey{}, r)
}

// ResolversFrom returns the pool ctx carries, or Default when it carries none.
func ResolversFrom(ctx context.Context) *Resolvers {
	if ctx != nil {
		if r, ok := ctx.Value(resolversKey{}).(*Resolvers); ok && r != nil {
			return r
		}
	}
	return Default()
}

// SetResolverQPS sets how many queries per second the engine sends to any one
// resolver, across all its sessions. Zero or less removes the limit.
func SetResolverQPS(qps int) {
	shared.setQPS(qps)
}

// ResolverQPS returns the engine's limit on queries per second per resolver,
// zero when there is none.
func ResolverQPS() int {
	shared.Lock()
	defer shared.Unlock()

	return shared.qps
}

// limitedServer is a shared resolver that waits for the engine's rate limit
// before each query.
type limitedServer struct {
	types.Nameserver
	limiter *rate.Limiter
}

func (s *limitedServer) SendRequest(ctx context.Context, req types.Request, conns types.Conn) error {
	if err := s.limiter.Wait(ctx); err != nil {
		return err
	}
	return s.Nameserver.SendRequest(ctx, req, conns)
}

// Close keeps the shared resolver open; it outlives any one pool.
func (s *limitedServer) Close() {}

// registry holds one limitedServer per resolver address for the life of the
// engine, and expires their queries that go unanswered.
type registry struct {
	sync.Mutex
	qps     int
	servers map[string]*limitedServer
	expiry  sync.Once
}

var shared = &registry{qps: DefaultResolverQPS, servers: make(map[string]*limitedServer)}

func qpsLimit(qps int) rate.Limit {
	if qps <= 0 {
		return rate.Inf
	}
	return rate.Limit(qps)
}

func (r *registry) setQPS(qps int) {
	r.Lock()
	defer r.Unlock()

	r.qps = qps
	for _, s := range r.servers {
		s.limiter.SetLimit(qpsLimit(qps))
	}
}

func (r *registry) get(addr string) (*limitedServer, error) {
	key, err := resolverAddr(addr)
	if err != nil {
		return nil, err
	}

	r.Lock()
	defer r.Unlock()

	if s, found := r.servers[key]; found {
		return s, nil
	}

	ns := servers.NewNameserver(key)
	if ns == nil {
		return nil, fmt.Errorf("the resolver %q cannot be used", addr)
	}
	s := &limitedServer{Nameserver: ns, limiter: rate.NewLimiter(qpsLimit(r.qps), 1)}
	r.servers[key] = s

	r.expiry.Do(func() { go r.expire() })
	return s, nil
}

// expire answers each query that has waited longer than queryTimeout with
// no response, so its sender stops waiting.
func (r *registry) expire() {
	t := time.NewTicker(queryTimeout)
	defer t.Stop()

	for range t.C {
		r.Lock()
		servs := make([]*limitedServer, 0, len(r.servers))
		for _, s := range r.servers {
			servs = append(servs, s)
		}
		r.Unlock()

		for _, s := range servs {
			for _, req := range s.XchgManager().RemoveExpired(queryTimeout) {
				req.NoResponse()
				req.Release()
			}
		}
	}
}

// resolverAddr returns the resolver's address as host:port, with port 53
// when none is given. The host must be an IP address.
func resolverAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	host, port := addr, "53"
	if h, p, err := net.SplitHostPort(addr); err == nil {
		host, port = h, p
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("the resolver %q is not an IP address", addr)
	}
	return net.JoinHostPort(host, port), nil
}

// rotation hands out its resolvers in turn. Responses are matched to a
// resolver by IP address, so a pool should not hold two resolvers on the
// same address with different ports.
type rotation struct {
	sync.Mutex
	list   []types.Nameserver
	next   int
	lookup map[string]types.Nameserver
}

func newRotation(servs ...types.Nameserver) *rotation {
	r := &rotation{lookup: make(map[string]types.Nameserver)}
	for _, s := range servs {
		r.list = append(r.list, s)
		r.lookup[s.Address().IP.String()] = s
	}
	return r
}

func (r *rotation) Get(string) (types.Nameserver, error) {
	r.Lock()
	defer r.Unlock()

	if len(r.list) == 0 {
		return nil, errors.New("the pool has no resolvers")
	}
	s := r.list[r.next%len(r.list)]
	r.next = (r.next + 1) % len(r.list)
	return s, nil
}

func (r *rotation) Lookup(addr string) (types.Nameserver, error) {
	r.Lock()
	defer r.Unlock()

	if s, found := r.lookup[addr]; found {
		return s, nil
	}
	return nil, errors.New("the pool does not have the resolver")
}

func (r *rotation) All() []types.Nameserver {
	r.Lock()
	defer r.Unlock()

	return append([]types.Nameserver(nil), r.list...)
}

// Close leaves the shared resolvers open.
func (r *rotation) Close() {}
