// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	miekg "github.com/miekg/dns"
)

// testServer answers every A query with 192.0.2.1 and counts the queries.
type testServer struct {
	mu      sync.Mutex
	addr    string
	queries []string
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ts := &testServer{addr: pc.LocalAddr().String()}
	srv := &miekg.Server{PacketConn: pc, Handler: miekg.HandlerFunc(func(w miekg.ResponseWriter, req *miekg.Msg) {
		resp := new(miekg.Msg)
		resp.SetReply(req)

		q := req.Question[0]
		ts.mu.Lock()
		ts.queries = append(ts.queries, strings.ToLower(q.Name))
		ts.mu.Unlock()

		if q.Qtype == miekg.TypeA && strings.HasPrefix(strings.ToLower(q.Name), "www.") {
			rr, _ := miekg.NewRR(q.Name + " 300 IN A 192.0.2.1")
			resp.Answer = append(resp.Answer, rr)
		} else {
			resp.Rcode = miekg.RcodeNameError
		}
		_ = w.WriteMsg(resp)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return ts
}

func (ts *testServer) count() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	return len(ts.queries)
}

func noResolverLimit(t *testing.T) {
	qps := ResolverQPS()
	SetResolverQPS(0)
	t.Cleanup(func() { SetResolverQPS(qps) })
}

func exchange(t *testing.T, r *Resolvers, name string) *miekg.Msg {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msg := new(miekg.Msg)
	msg.SetQuestion(miekg.Fqdn(name), miekg.TypeA)
	for i := 0; i < 5; i++ {
		if resp, err := r.Exchange(ctx, msg.Copy()); err == nil {
			return resp
		}
	}
	t.Fatalf("no answer for %s", name)
	return nil
}

func TestResolverAddr(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.53":         "192.0.2.53:53",
		" 192.0.2.53:5353 ":  "192.0.2.53:5353",
		"2001:db8::53":       "[2001:db8::53]:53",
		"[2001:db8::53]:853": "[2001:db8::53]:853",
	} {
		if got, err := resolverAddr(in); err != nil || got != want {
			t.Errorf("resolverAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "dns.example.com", "dns.example.com:53", "192.0.2.300"} {
		if _, err := resolverAddr(bad); err == nil {
			t.Errorf("resolverAddr(%q) was accepted", bad)
		}
	}
	if _, err := NewResolvers([]string{"dns.example.com"}, ""); err == nil {
		t.Error("a pool was built with a host name for a resolver")
	}
	if _, err := NewResolvers(nil, "dns.example.com"); err == nil {
		t.Error("a pool was built with a host name for the wildcard resolver")
	}
}

func TestNewSessionResolversPicksTheQueryAndWildcardResolvers(t *testing.T) {
	noResolverLimit(t)

	if r, err := NewSessionResolvers(nil, nil); r != nil || err != nil {
		t.Fatalf("without settings, NewSessionResolvers = %v, %v; want the default pool", r, err)
	}

	untrusted, trusted := startTestServer(t), startTestServer(t)

	// The untrusted resolvers take the queries; the trusted one tests for wildcards.
	r, err := NewSessionResolvers([]string{untrusted.addr}, []string{trusted.addr})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	resp := exchange(t, r, "www.example.com")
	if untrusted.count() == 0 || trusted.count() != 0 {
		t.Fatalf("queries: %d untrusted, %d trusted; want the untrusted resolver only",
			untrusted.count(), trusted.count())
	}
	r.WildcardDetected(context.Background(), resp, "example.com")
	if trusted.count() == 0 {
		t.Error("the wildcard tests did not go to the trusted resolver")
	}

	// With only trusted resolvers, they take the queries too.
	before := trusted.count()
	r2, err := NewSessionResolvers(nil, []string{trusted.addr})
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Stop()
	exchange(t, r2, "www.example.org")
	if trusted.count() == before {
		t.Error("the trusted resolver did not take the queries")
	}
}

func TestTheResolverLimitHoldsAcrossPools(t *testing.T) {
	qps := ResolverQPS()
	t.Cleanup(func() { SetResolverQPS(qps) })
	SetResolverQPS(2)
	if ResolverQPS() != 2 {
		t.Fatalf("ResolverQPS = %d, want 2", ResolverQPS())
	}

	ts := startTestServer(t)
	a, err := NewResolvers([]string{ts.addr}, ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	b, err := NewResolvers([]string{ts.addr}, ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	// Two pools share the resolver, so four queries at two per second take
	// at least a second and a half, whichever pool sends them.
	start := time.Now()
	for _, r := range []*Resolvers{a, b, a, b} {
		exchange(t, r, "www.example.com")
	}
	if elapsed := time.Since(start); elapsed < 1400*time.Millisecond {
		t.Errorf("four queries took %v; the shared limit of two per second was not kept", elapsed)
	}
}

func TestStoppingAPoolLeavesTheSharedResolver(t *testing.T) {
	noResolverLimit(t)

	ts := startTestServer(t)
	a, err := NewResolvers([]string{ts.addr}, ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewResolvers([]string{ts.addr}, ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()

	a.Stop()
	a.Stop() // a second Stop is harmless

	msg := new(miekg.Msg)
	msg.SetQuestion("www.example.com.", miekg.TypeA)
	if _, err := a.Exchange(context.Background(), msg); err == nil {
		t.Error("a stopped pool answered a query")
	}
	if resp := exchange(t, b, "www.example.com"); len(resp.Answer) != 1 {
		t.Errorf("the other pool's answer = %v", resp.Answer)
	}
}

func TestResolversFromTheContext(t *testing.T) {
	if ResolversFrom(context.Background()) != Default() || Default() == nil {
		t.Error("a context without a pool did not give the default pool")
	}

	noResolverLimit(t)
	ts := startTestServer(t)
	r, err := NewResolvers([]string{ts.addr}, ts.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	if got := ResolversFrom(WithResolvers(context.Background(), r)); got != r {
		t.Error("the context's pool was not returned")
	}
}
