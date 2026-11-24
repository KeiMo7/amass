// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the Apache 2 LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const testSecret = "correct-horse-battery-staple"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

func newLoadedStore(t *testing.T, creds []Credential, opts ...Option) *Store {
	t.Helper()
	s := NewStore(opts...)
	if err := s.Replace(creds); err != nil {
		t.Fatalf("Replace failed: %v", err)
	}
	return s
}

func TestAuthenticateMissingAndForged(t *testing.T) {
	s := newLoadedStore(t, []Credential{{KeyID: "alice", Secret: testSecret}})

	if _, err := s.Authenticate("10.0.0.1", "", ""); err == nil {
		t.Fatal("expected error for empty credentials")
	}
	if _, err := s.Authenticate("10.0.0.1", "alice", "wrong-secret-value"); err != ErrForged {
		t.Fatalf("expected ErrForged, got %v", err)
	}
	// Unknown key ID must look exactly like a bad password: forged, not a
	// distinct "no such user" category.
	if _, err := s.Authenticate("10.0.0.1", "nobody", testSecret); err != ErrForged {
		t.Fatalf("expected ErrForged for unknown id, got %v", err)
	}

	p, err := s.Authenticate("10.0.0.1", "alice", testSecret)
	if err != nil {
		t.Fatalf("valid credentials rejected: %v", err)
	}
	if p.KeyID != "alice" || !p.CanWrite() {
		t.Fatalf("unexpected principal: %+v", p)
	}
}

func TestSecretLengthEnforced(t *testing.T) {
	s := NewStore()
	err := s.Replace([]Credential{{KeyID: "weak", Secret: "short"}})
	if err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("expected minimum length error, got %v", err)
	}
}

func TestExpiredCredential(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	s := newLoadedStore(t, []Credential{{
		KeyID:     "exp",
		Secret:    testSecret,
		ExpiresAt: now.Add(time.Minute),
	}}, WithClock(clock))

	if _, err := s.Authenticate("src", "exp", testSecret); err != nil {
		t.Fatalf("credential should be valid before expiry: %v", err)
	}

	// Advance the clock past expiry by rebuilding with a later clock.
	later := NewStore(WithClock(func() time.Time { return now.Add(2 * time.Minute) }))
	if err := later.Replace([]Credential{{KeyID: "exp", Secret: testSecret, ExpiresAt: now.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := later.Authenticate("src", "exp", testSecret); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestRevocation(t *testing.T) {
	s := newLoadedStore(t, []Credential{{KeyID: "rev", Secret: testSecret}})
	ch := s.RevocationChannel()

	if err := s.Revoke("rev"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("revocation watcher was not signalled")
	}
	if _, err := s.Authenticate("src", "rev", testSecret); err != ErrRevoked {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
	if !s.IsRevoked("rev") {
		t.Fatal("IsRevoked should report true after revocation")
	}
	// A new watcher generation must be available after the broadcast.
	next := s.RevocationChannel()
	select {
	case <-next:
		t.Fatal("fresh watcher channel must start open")
	default:
	}
}

func TestSessionScopeAndReadOnly(t *testing.T) {
	s1, s2 := uuid.New(), uuid.New()
	s := newLoadedStore(t, []Credential{
		{KeyID: "scoped", Secret: testSecret, Sessions: []uuid.UUID{s1}},
		{KeyID: "viewer", Secret: testSecret + "2", ReadOnly: true},
	})

	p, err := s.Authenticate("src", "scoped", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CanAccessSession(s1) || p.CanAccessSession(s2) {
		t.Fatal("session scope not enforced on principal")
	}
	got := p.VisibleSessions([]uuid.UUID{s1, s2, uuid.New()})
	if len(got) != 1 || got[0] != s1 {
		t.Fatalf("VisibleSessions returned %v", got)
	}

	viewer, err := s.Authenticate("src", "viewer", testSecret+"2")
	if err != nil {
		t.Fatal(err)
	}
	if viewer.CanWrite() {
		t.Fatal("read-only principal must not be writable")
	}
	if !viewer.CanAccessSession(s2) {
		t.Fatal("read-only credential without scope should see all sessions")
	}
}

func TestThrottleAndRecovery(t *testing.T) {
	s := NewStore(WithMaxFailures(3), WithFailureWindow(time.Minute))
	if err := s.Replace([]Credential{{KeyID: "alice", Secret: testSecret}}); err != nil {
		t.Fatal(err)
	}
	const src = "203.0.113.9"

	for i := 0; i < 3; i++ {
		if _, err := s.Authenticate(src, "alice", "bad"); err != ErrForged {
			t.Fatalf("attempt %d: expected ErrForged, got %v", i, err)
		}
	}
	// Even the correct secret is now refused while throttled, so brute force
	// cannot continue.
	if _, err := s.Authenticate(src, "alice", testSecret); err != ErrThrottled {
		t.Fatalf("expected ErrThrottled, got %v", err)
	}
	// Throttling is per-source: another caller with the correct credential is
	// unaffected.
	if _, err := s.Authenticate("203.0.113.10", "alice", testSecret); err != nil {
		t.Fatalf("legitimate caller must not be throttled: %v", err)
	}
	// A successful authentication from the locked source clears its counter
	// once the window elapses; emulate by waiting on a fresh short-window
	// store instead of sleeping.
	s2 := NewStore(WithMaxFailures(3), WithFailureWindow(time.Millisecond), WithClock(func() time.Time {
		return time.Now()
	}))
	_ = s2.Replace([]Credential{{KeyID: "alice", Secret: testSecret}})
	for i := 0; i < 3; i++ {
		_, _ = s2.Authenticate(src, "alice", "bad")
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := s2.Authenticate(src, "alice", testSecret); err != nil {
		t.Fatalf("counter should reset after window: %v", err)
	}
}

func TestFingerprintIsIrreversibleAndStable(t *testing.T) {
	s := newLoadedStore(t, []Credential{{KeyID: "alice", Secret: testSecret}})
	fp := s.Fingerprint("alice")
	if !strings.HasPrefix(fp, "fp_") {
		t.Fatalf("unexpected fingerprint shape: %s", fp)
	}
	if strings.Contains(fp, testSecret) || strings.Contains(fp, "alice") {
		t.Fatal("fingerprint must not contain the raw key ID or secret")
	}
	if s.Fingerprint("alice") != fp {
		t.Fatal("fingerprint must be stable for the same credential")
	}
	// Unknown IDs still produce a non-reversible placeholder rather than the
	// raw identifier.
	unknown := s.Fingerprint("ghost")
	if strings.Contains(unknown, "ghost") {
		t.Fatal("unknown-id fingerprint must not echo the key ID")
	}
}

// TestMiddlewareDenyBodies confirms the externally visible error contract and
// ensures credentials never appear in the response body.
func TestMiddlewareDenyBodies(t *testing.T) {
	s := newLoadedStore(t, []Credential{{KeyID: "alice", Secret: testSecret}})
	mw := NewMiddleware(s, false, testLogger())

	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	// Missing credentials -> 401 with WWW-Authenticate.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/list", nil)
	req.RemoteAddr = "203.0.113.5:5123"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 must carry a WWW-Authenticate challenge")
	}

	// Forged credentials -> 401, body identical in shape, no secret echoed.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sessions/list", nil)
	req.RemoteAddr = "203.0.113.5:5123"
	req.SetBasicAuth("alice", "definitely-wrong")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "definitely-wrong") {
		t.Fatal("response body must not contain the presented secret")
	}
	if !strings.Contains(body, "authentication required") {
		t.Fatalf("unexpected body: %s", body)
	}

	// Read-only credential attempting a write -> 403.
	ro := newLoadedStore(t, []Credential{{KeyID: "ro", Secret: testSecret, ReadOnly: true}})
	roMW := NewMiddleware(ro, false, testLogger())
	roH := roMW.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("read-only write must never reach the handler")
	}))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
	req.RemoteAddr = "203.0.113.5:5123"
	req.SetBasicAuth("ro", testSecret)
	roH.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestOpenModeLoopbackOnly(t *testing.T) {
	s := NewStore() // deliberately empty
	mw := NewMiddleware(s, true, testLogger())
	h := mw.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFromContext(r.Context()) == nil {
			t.Error("loopback open-mode request should carry a principal")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Loopback succeeds without any credential.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions/list", nil)
	req.RemoteAddr = "127.0.0.1:4444"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback open mode should pass, got %d", rec.Code)
	}

	// Non-loopback is rejected even in open mode.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/sessions/list", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-loopback open mode must be rejected, got %d", rec.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:4000": true,
		"127.0.0.1":      true,
		"localhost:4000": true,
		"[::1]:4000":     true,
		":4000":          false,
		"0.0.0.0:4000":   false,
		"10.0.0.1:4000":  false,
		"[::]:4000":      false,
	}
	for addr, want := range cases {
		if got := IsLoopbackAddr(addr); got != want {
			t.Errorf("IsLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
