// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/api/auth"
	"github.com/owasp-amass/amass/v5/engine/api/server"
	"github.com/owasp-amass/amass/v5/engine/api/server/testsupport"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

const (
	adminID     = "admin"
	scopedID    = "scoped"
	otherID     = "other"
	roID        = "viewer"
	adminSecret = "admin-secret-value-123456"
	scopedSec   = "scoped-secret-value-1234"
	otherSec    = "other-secret-value-12345"
	roSecret    = "readonly-secret-123456"
)

type testHarness struct {
	srv     *server.Server
	baseURL string
	mgr     *testsupport.FakeManager
	logBuf  *bytes.Buffer
}

func writeCreds(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	return p
}

func credYAML(sessions map[string]uuid.UUID, expiry map[string]time.Time) string {
	var b strings.Builder
	b.WriteString("credentials:\n")
	type row struct {
		id, secret string
		ro         bool
		sess       []uuid.UUID
		exp        time.Time
	}
	rows := []row{
		{adminID, adminSecret, false, nil, expiry[adminID]},
		{scopedID, scopedSec, false, []uuid.UUID{sessions["a"]}, expiry[scopedID]},
		{otherID, otherSec, false, []uuid.UUID{sessions["b"]}, expiry[otherID]},
		{roID, roSecret, true, nil, expiry[roID]},
	}
	for _, r := range rows {
		b.WriteString(fmt.Sprintf("  - id: %s\n    secret: %s\n", r.id, r.secret))
		if r.ro {
			b.WriteString("    readOnly: true\n")
		}
		if !r.exp.IsZero() {
			b.WriteString("    expiresAt: " + r.exp.UTC().Format(time.RFC3339Nano) + "\n")
		}
		if len(r.sess) > 0 {
			b.WriteString("    sessions:\n")
			for _, s := range r.sess {
				b.WriteString("      - " + s.String() + "\n")
			}
		}
	}
	return b.String()
}

func startServer(t *testing.T, addr, credContent string, preload []uuid.UUID, opts ...auth.Option) *testHarness {
	t.Helper()
	mgr := testsupport.NewFakeManager()
	for _, id := range preload {
		if err := mgr.AddSession(testsupport.NewFakeSession(id)); err != nil {
			t.Fatal(err)
		}
	}
	dis := testsupport.FakeDispatcher{}
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	cfg := server.Config{Addr: addr, AuthOptions: opts}
	if credContent != "" {
		cfg.CredentialFile = writeCreds(t, credContent)
	}

	srv, err := server.NewServer(logger, dis, mgr, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	// Wait until the listener accepts connections.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", srv.Addr(), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	return &testHarness{
		srv:     srv,
		baseURL: "http://" + srv.Addr() + "/api/v1",
		mgr:     mgr,
		logBuf:  logBuf,
	}
}

func basic(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func (h *testHarness) do(t *testing.T, method, path, authz string, body string) *http.Response {
	t.Helper()
	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, h.baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request %s %s: %v", method, path, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := &bytes.Buffer{}
	_, _ = buf.ReadFrom(resp.Body)
	return buf.String()
}

func newSessions(t *testing.T, h *testHarness) (a, b uuid.UUID) {
	sa := testsupport.NewFakeSession(uuid.New())
	sb := testsupport.NewFakeSession(uuid.New())
	if err := h.mgr.AddSession(sa); err != nil {
		t.Fatal(err)
	}
	if err := h.mgr.AddSession(sb); err != nil {
		t.Fatal(err)
	}
	return sa.ID(), sb.ID()
}

// Form 8: the health probe is public, stateless and leaks no session data.
func TestHealthEndpointPublic(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)

	resp := h.do(t, http.MethodGet, "/health", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health without credentials: expected 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Amass Engine OK") {
		t.Fatalf("unexpected health body: %s", body)
	}
	if strings.Contains(strings.ToLower(body), "session") {
		t.Fatal("health response must not mention sessions")
	}
}

// Form 1: no credentials on any read/write endpoint is rejected.
func TestNoCredentialsRejectedEverywhere(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)
	a, _ := newSessions(t, h)

	paths := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/sessions/list", ""},
		{http.MethodPost, "/sessions", "{}"},
		{http.MethodDelete, "/sessions/" + a.String(), ""},
		{http.MethodGet, "/sessions/" + a.String() + "/stats", ""},
		{http.MethodGet, "/sessions/" + a.String() + "/scope/fqdn", ""},
		{http.MethodPost, "/sessions/" + a.String() + "/assets/fqdn", "{}"},
		{http.MethodPost, "/sessions/" + a.String() + "/assets/fqdn:bulk", `{"items":[]}`},
	}
	for _, p := range paths {
		resp := h.do(t, p.method, p.path, "", p.body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s without credentials: expected 401, got %d", p.method, p.path, resp.StatusCode)
		}
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s %s: missing WWW-Authenticate challenge", p.method, p.path)
		}
	}
}

// Forms 2 + indistinguishability: scoped credentials, and cross-scope access
// looks identical to access of a non-existent session.
func TestScopedCredentialAndIndistinguishability(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	sessions := map[string]uuid.UUID{"a": a, "b": b}
	h := startServer(t, "127.0.0.1:0", credYAML(sessions, nil), []uuid.UUID{a, b})

	// scoped credential can read its own session's stats.
	resp := h.do(t, http.MethodGet, "/sessions/"+a.String()+"/stats", basic(scopedID, scopedSec), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scoped read of own session: expected 200, got %d body=%s", resp.StatusCode, readBody(t, resp))
	}

	// Cross-scope access of an existing session.
	cross := h.do(t, http.MethodGet, "/sessions/"+b.String()+"/stats", basic(scopedID, scopedSec), "")
	// Access of a random, non-existent session.
	ghost := h.do(t, http.MethodGet, "/sessions/"+uuid.New().String()+"/stats", basic(scopedID, scopedSec), "")

	if cross.StatusCode != http.StatusNotFound || ghost.StatusCode != http.StatusNotFound {
		t.Fatalf("expected both 404, got cross=%d ghost=%d", cross.StatusCode, ghost.StatusCode)
	}
	crossBody := readBody(t, cross)
	ghostBody := readBody(t, ghost)
	if crossBody != ghostBody {
		t.Fatalf("response bodies differ and leak session existence:\n cross=%s\n ghost=%s", crossBody, ghostBody)
	}
	var errResp struct {
		Error   string `json:"error"`
		Details string `json:"details"`
		Code    int    `json:"code"`
	}
	if err := json.Unmarshal([]byte(crossBody), &errResp); err != nil {
		t.Fatalf("error body not JSON: %v", err)
	}
	if errResp.Code != http.StatusNotFound || errResp.Error != "session not found" {
		t.Fatalf("unexpected error payload: %+v", errResp)
	}

	// The list endpoint only reveals sessions inside the credential's scope.
	list := h.do(t, http.MethodGet, "/sessions/list", basic(scopedID, scopedSec), "")
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", list.StatusCode)
	}
	var listed struct {
		SessionTokens []string `json:"sessionTokens"`
	}
	if err := json.Unmarshal([]byte(readBody(t, list)), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.SessionTokens) != 1 || listed.SessionTokens[0] != a.String() {
		t.Fatalf("scoped list leaked other sessions: %v", listed.SessionTokens)
	}

	// The unrestricted admin credential sees both.
	adminList := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, adminSecret), "")
	var adminShown struct {
		SessionTokens []string `json:"sessionTokens"`
	}
	_ = json.Unmarshal([]byte(readBody(t, adminList)), &adminShown)
	if len(adminShown.SessionTokens) != 2 {
		t.Fatalf("admin should see all sessions, got %v", adminShown.SessionTokens)
	}
}

// Form 3: expired, revoked and forged credentials are all rejected.
func TestExpiredRevokedForged(t *testing.T) {
	content := credYAML(nil, nil) +
		"  - id: expiredone\n    secret: expired-secret-123456\n    expiresAt: " +
		time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano) + "\n"
	h := startServer(t, "127.0.0.1:0", content, nil)
	a, _ := newSessions(t, h)

	// Forged: wrong secret and unknown ID both yield the same 401.
	if r := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, "wrong-password-xyz"), ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged secret: expected 401, got %d", r.StatusCode)
	}
	if r := h.do(t, http.MethodGet, "/sessions/list", basic("nosuchid", adminSecret), ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown id: expected 401, got %d", r.StatusCode)
	}

	// Expired.
	if r := h.do(t, http.MethodGet, "/sessions/"+a.String()+"/stats", basic("expiredone", "expired-secret-123456"), ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired credential: expected 401, got %d", r.StatusCode)
	}
}

// Form 4: a read-only credential cannot create sessions or terminate tasks.
func TestReadOnlyCannotWrite(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)
	a, _ := newSessions(t, h)

	// Reads are allowed.
	if r := h.do(t, http.MethodGet, "/sessions/"+a.String()+"/stats", basic(roID, roSecret), ""); r.StatusCode != http.StatusOK {
		t.Fatalf("read-only read: expected 200, got %d", r.StatusCode)
	}

	// Mutations are forbidden with a distinct 403 status.
	if r := h.do(t, http.MethodPost, "/sessions", basic(roID, roSecret), "{}"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only create: expected 403, got %d", r.StatusCode)
	}
	if r := h.do(t, http.MethodDelete, "/sessions/"+a.String(), basic(roID, roSecret), ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only terminate: expected 403, got %d", r.StatusCode)
	}
	if r := h.do(t, http.MethodPost, "/sessions/"+a.String()+"/assets/fqdn", basic(roID, roSecret), "{}"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only asset write: expected 403, got %d", r.StatusCode)
	}

	// A writable credential can still create a session through the API.
	r := h.do(t, http.MethodPost, "/sessions", basic(adminID, adminSecret), `{"scope":{}}`)
	if r.StatusCode != http.StatusCreated {
		t.Fatalf("admin create session: expected 201, got %d body=%s", r.StatusCode, readBody(t, r))
	}
	var created struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal([]byte(readBody(t, r)), &created); err != nil || created.SessionToken == "" {
		t.Fatalf("missing session token in create response: %v", err)
	}
}

// Form 5: the same credential concurrently drives multiple endpoints without
// interference.
func TestConcurrentAccessSameCredential(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)
	a, _ := newSessions(t, h)

	var wg sync.WaitGroup
	errs := make(chan error, 30)
	for i := 0; i < 10; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			r := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, adminSecret), "")
			if r.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("list %d", r.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			r := h.do(t, http.MethodGet, "/sessions/"+a.String()+"/stats", basic(adminID, adminSecret), "")
			if r.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("stats %d", r.StatusCode)
			}
		}()
		go func() {
			defer wg.Done()
			r := h.do(t, http.MethodGet, "/health", "", "")
			if r.StatusCode != http.StatusOK {
				errs <- fmt.Errorf("health %d", r.StatusCode)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Throttling: repeated failures lock out the source, but a different source
// using the correct credential is unaffected.
func TestThrottlingDoesNotAffectLegitimateCaller(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil,
		auth.WithMaxFailures(3), auth.WithFailureWindow(time.Minute))

	for i := 0; i < 3; i++ {
		if r := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, "garbage-secret-99"), ""); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, r.StatusCode)
		}
	}
	// The brute-forcing source now receives 429 even with the right secret.
	if r := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, adminSecret), ""); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled source: expected 429, got %d", r.StatusCode)
	}
}

// Hard constraint 5: no key material + non-loopback bind must fail to start;
// a loopback bind starts with an explicit warning.
func TestStartupKeyMaterialPolicy(t *testing.T) {
	mgr := testsupport.NewFakeManager()
	dis := testsupport.FakeDispatcher{}
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// Non-loopback, no credentials: hard failure.
	if _, err := server.NewServer(logger, dis, mgr, server.Config{Addr: "0.0.0.0:0"}); err == nil {
		t.Fatal("expected startup failure when binding non-loopback without credentials")
	} else if !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("unexpected startup error: %v", err)
	}

	// Loopback, no credentials: starts and warns.
	srv, err := server.NewServer(logger, dis, mgr, server.Config{Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("loopback open mode should start: %v", err)
	}
	_ = srv.Shutdown()
	if !strings.Contains(logBuf.String(), "OPEN MODE") {
		t.Fatalf("expected an explicit open-mode warning, logs were: %s", logBuf.String())
	}
}

// Constraint: credentials must never appear in access logs, error responses or
// audit records; only irreversible identifiers may be present.
func TestNoSecretMaterialInLogsOrErrors(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)

	_ = h.do(t, http.MethodGet, "/sessions/list", basic(adminID, "super-wrong-secret"), "")
	_ = h.do(t, http.MethodGet, "/sessions/list", basic(adminID, adminSecret), "")
	_ = h.do(t, http.MethodGet, "/sessions/"+uuid.New().String()+"/stats", basic(adminID, adminSecret), "")

	logs := h.logBuf.String()
	for _, secret := range []string{adminSecret, scopedSec, otherSec, roSecret, "super-wrong-secret"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("raw secret leaked into logs: %q", secret)
		}
	}
	if !strings.Contains(logs, "fp_") {
		t.Fatal("logs should contain the irreversible fingerprint identifier")
	}

	// Error responses must not echo the presented credential either.
	resp := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, "another-bad-secret"), "")
	body := readBody(t, resp)
	if strings.Contains(body, "another-bad-secret") {
		t.Fatal("error response echoed the secret")
	}
}

// Existing-behavior guard: request and response structures are unchanged.
func TestResponseShapesUnchanged(t *testing.T) {
	h := startServer(t, "127.0.0.1:0", credYAML(nil, nil), nil)
	a := uuid.New()
	if err := h.mgr.AddSession(testsupport.NewFakeSession(a)); err != nil {
		t.Fatal(err)
	}

	resp := h.do(t, http.MethodGet, "/sessions/"+a.String()+"/stats", basic(adminID, adminSecret), "")
	var stats et.SessionStats
	if err := json.Unmarshal([]byte(readBody(t, resp)), &stats); err != nil {
		t.Fatalf("stats response shape changed: %v", err)
	}

	list := h.do(t, http.MethodGet, "/sessions/list", basic(adminID, adminSecret), "")
	var out struct {
		SessionTokens []string `json:"sessionTokens"`
	}
	if err := json.Unmarshal([]byte(readBody(t, list)), &out); err != nil {
		t.Fatalf("list response shape changed: %v", err)
	}
	if len(out.SessionTokens) != 1 || out.SessionTokens[0] != a.String() {
		t.Fatalf("unexpected list payload: %v", out)
	}
}
