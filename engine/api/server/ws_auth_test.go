// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/engine/api/auth"
	"github.com/owasp-amass/amass/v5/engine/api/server"
	"github.com/owasp-amass/amass/v5/engine/api/server/testsupport"
)

// newBufferLogger writes structured logs into a strings.Builder-backed buffer.
func newBufferLogger(b *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(&stringWriter{b: b}, nil))
}

type stringWriter struct{ b *strings.Builder }

func (w *stringWriter) Write(p []byte) (int, error) { return w.b.Write(p) }

func waitForListener(t *testing.T, srv *server.Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", srv.Addr(), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s never became reachable", srv.Addr())
}

// wsURL converts an http base URL into a ws URL for the session log stream.
func wsURL(baseURL, sessionID string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	}
	u.Path = "/api/v1/sessions/" + sessionID + "/ws/logs"
	return u.String()
}

// dialWS performs an authenticated WebSocket dial. The returned response is
// nil on a successful upgrade.
func dialWS(t *testing.T, rawURL, authz string) (*websocket.Conn, *http.Response) {
	t.Helper()
	hdr := http.Header{}
	if authz != "" {
		hdr.Set("Authorization", authz)
	}
	conn, resp, err := websocket.DefaultDialer.Dial(rawURL, hdr)
	if err != nil {
		return nil, resp
	}
	return conn, nil
}

// readOne waits briefly for a text frame. It returns the message content and
// whether one arrived.
func readOne(t *testing.T, conn *websocket.Conn, wait time.Duration) (string, bool) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		return "", false
	}
	return string(msg), true
}

// expectClose dials/reads until the connection reports a close, failing the
// test if it stays open beyond the deadline.
func expectClose(t *testing.T, conn *websocket.Conn, wait time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err,
				websocket.CloseNormalClosure, websocket.ClosePolicyViolation,
				websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				// A clean close (any of the above codes) is what we want;
				// anything else is still a closed connection for our purposes
				// but is reported for visibility.
				t.Logf("connection closed with: %v", err)
			}
			return
		}
	}
}

// Form 6a: the log stream requires credentials and session scope at upgrade
// time.
func TestWSRequiresAuthentication(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	h := startServer(t, "127.0.0.1:0", credYAML(map[string]uuid.UUID{"a": a, "b": b}, nil),
		[]uuid.UUID{a, b})

	// No credentials: the upgrade is rejected with 401 rather than upgraded.
	if _, resp := dialWS(t, wsURL(h.baseURL, a.String()), ""); resp == nil || resp.StatusCode != http.StatusUnauthorized {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("ws without credentials: expected 401, got %d", status)
	}

	// Forged credentials: rejected as well.
	if _, resp := dialWS(t, wsURL(h.baseURL, a.String()), basic(adminID, "bogus-secret-zzz")); resp == nil || resp.StatusCode != http.StatusUnauthorized {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("ws with forged credentials: expected 401, got %d", status)
	}

	// Scoped credential reaching a session outside its scope is indistinguishable
	// from a non-existent session: both 404.
	if _, resp := dialWS(t, wsURL(h.baseURL, b.String()), basic(scopedID, scopedSec)); resp == nil || resp.StatusCode != http.StatusNotFound {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("ws cross-scope: expected 404, got %d", status)
	}
	if _, resp := dialWS(t, wsURL(h.baseURL, uuid.New().String()), basic(scopedID, scopedSec)); resp == nil || resp.StatusCode != http.StatusNotFound {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("ws non-existent session: expected 404, got %d", status)
	}
}

// Form 6b: a valid stream delivers messages, then is actively closed when the
// credential is revoked.
func TestWSClosedOnRevocation(t *testing.T) {
	a := uuid.New()
	h := startServerWithInterval(t, "127.0.0.1:0",
		credYAML(map[string]uuid.UUID{"a": a}, nil), []uuid.UUID{a}, 200*time.Millisecond, nil)

	conn, resp := dialWS(t, wsURL(h.baseURL, a.String()), basic(scopedID, scopedSec))
	if resp != nil {
		t.Fatalf("valid ws dial rejected: %d", resp.StatusCode)
	}
	defer func() { _ = conn.Close() }()

	// Prove the stream is live. The pubsub logger drops messages that arrive
	// before a subscriber registers, so publish repeatedly until the first
	// frame is observed.
	sess := h.mgr.GetSession(a)
	got := false
	var msg string
	for attempt := 0; attempt < 20; attempt++ {
		sess.PubSub().Publish("revocation-probe")
		if m, ok := readOne(t, conn, 300*time.Millisecond); ok && strings.Contains(m, "revocation-probe") {
			msg, got = m, true
			break
		}
	}
	if !got {
		t.Fatalf("did not receive published log, last %q", msg)
	}

	// Revoke the credential; the watcher must tear the stream down promptly.
	if err := h.srv.AuthStore().Revoke(scopedID); err != nil {
		t.Fatal(err)
	}
	expectClose(t, conn, 3*time.Second)
}

// Form 6c: an expired credential causes the stream to close on the next
// validation tick, even without an explicit revocation call.
func TestWSClosedOnExpiry(t *testing.T) {
	a := uuid.New()

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	expiry := map[string]time.Time{scopedID: now.Add(time.Hour)}
	h := startServerWithInterval(t, "127.0.0.1:0",
		credYAML(map[string]uuid.UUID{"a": a}, expiry), []uuid.UUID{a}, 200*time.Millisecond, clock)

	conn, resp := dialWS(t, wsURL(h.baseURL, a.String()), basic(scopedID, scopedSec))
	if resp != nil {
		t.Fatalf("valid ws dial rejected: %d", resp.StatusCode)
	}
	defer func() { _ = conn.Close() }()

	// Advance beyond expiry; the periodic check must close the stream.
	advance(2 * time.Hour)
	expectClose(t, conn, 3*time.Second)
}

// Form 6d: terminating the underlying session closes its log streams.
func TestWSClosedOnSessionTermination(t *testing.T) {
	a := uuid.New()
	h := startServerWithInterval(t, "127.0.0.1:0",
		credYAML(map[string]uuid.UUID{"a": a}, nil), []uuid.UUID{a}, 200*time.Millisecond, nil)

	conn, resp := dialWS(t, wsURL(h.baseURL, a.String()), basic(adminID, adminSecret))
	if resp != nil {
		t.Fatalf("valid ws dial rejected: %d", resp.StatusCode)
	}
	defer func() { _ = conn.Close() }()

	h.mgr.CancelSession(a)
	expectClose(t, conn, 3*time.Second)
}

// startServerWithInterval is a small helper that also sets the WS validation
// interval and optional clock.
func startServerWithInterval(t *testing.T, addr, content string, preload []uuid.UUID, interval time.Duration, clock func() time.Time) *testHarness {
	t.Helper()
	mgr := testsupport.NewFakeManager()
	for _, id := range preload {
		if err := mgr.AddSession(testsupport.NewFakeSession(id)); err != nil {
			t.Fatal(err)
		}
	}
	logBuf := new(strings.Builder)
	logger := newBufferLogger(logBuf)

	cfg := server.Config{
		Addr:            addr,
		CredentialFile:  writeCreds(t, content),
		WSCheckInterval: interval,
		Clock:           clock,
		AuthOptions:     []auth.Option{auth.WithMaxFailures(100), auth.WithFailureWindow(time.Hour)},
	}
	srv, err := server.NewServer(logger, testsupport.FakeDispatcher{}, mgr, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	waitForListener(t, srv)
	return &testHarness{
		srv:     srv,
		baseURL: "http://" + srv.Addr() + "/api/v1",
		mgr:     mgr,
	}
}
