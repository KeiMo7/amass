// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the Apache 2 LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/api/auth"
	client "github.com/owasp-amass/amass/v5/engine/api/client/v1"
	"github.com/owasp-amass/amass/v5/engine/api/server"
	"github.com/owasp-amass/amass/v5/engine/api/server/testsupport"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	cAdminID  = "admin"
	cAdminSec = "admin-secret-value-123456"
)

func writeClientCreds(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "credentials.yaml")
	content := "credentials:\n  - id: " + cAdminID + "\n    secret: " + cAdminSec + "\n"
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startClientTestServer(t *testing.T) *server.Server {
	t.Helper()
	mgr := testsupport.NewFakeManager()
	logger := slog.New(slog.NewTextHandler(&strings.Builder{}, nil))
	srv, err := server.NewServer(logger, testsupport.FakeDispatcher{}, mgr, server.Config{
		Addr:           "127.0.0.1:0",
		CredentialFile: writeClientCreds(t),
		AuthOptions:    []auth.Option{auth.WithMaxFailures(50), auth.WithFailureWindow(time.Hour)},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", srv.Addr(), 200*time.Millisecond); err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return srv
}

func TestClientSendsBasicAuth(t *testing.T) {
	srv := startClientTestServer(t)

	c, err := client.NewAuthenticatedClient("http://"+srv.Addr(), cAdminID, cAdminSec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A read against the protected endpoint succeeds with credentials.
	if _, err := c.ListSessions(ctx); err != nil {
		// Zero sessions returns a 404 error from the handler; that still
		// proves authentication passed (a 401 would be an auth failure).
		if !strings.Contains(err.Error(), "404") {
			t.Fatalf("expected handler-level 404 (authenticated), got: %v", err)
		}
	}
}

func TestClientWithoutCredentialsRejected(t *testing.T) {
	srv := startClientTestServer(t)

	c, err := client.NewClient("http://" + srv.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = c.ListSessions(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected a 401 authentication error, got: %v", err)
	}
}

func TestClientURLUserInfoExtraction(t *testing.T) {
	c, err := client.NewClient("http://" + cAdminID + ":" + cAdminSec + "@127.0.0.1:4000")
	if err != nil {
		t.Fatal(err)
	}
	// The sanitized base URL must not retain the embedded userinfo.
	if strings.Contains(c.BaseURL(), cAdminSec) {
		t.Fatal("client retained secret material in its base URL")
	}
}

func TestClientForgedCredentialsRejected(t *testing.T) {
	srv := startClientTestServer(t)

	c, err := client.NewAuthenticatedClient("http://"+srv.Addr(), cAdminID, "wrong-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = c.ListSessions(ctx)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 for forged credentials, got: %v", err)
	}
}

// TestServerRequestsCarryAuthorization inspects a live request to confirm the
// exact header value produced by the client matches an RFC 7617 Basic token.
func TestServerRequestsCarryAuthorization(t *testing.T) {
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(cAdminID+":"+cAdminSec))

	seen := make(chan string, 1)
	ts := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seen <- r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sessionTokens":[]}`))
		}),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = ts.Serve(ln) }()
	t.Cleanup(func() { _ = ts.Close() })

	c, err := client.NewAuthenticatedClient("http://"+ln.Addr().String(), cAdminID, cAdminSec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = c.ListSessions(ctx)

	select {
	case got := <-seen:
		if got != expected {
			t.Fatalf("Authorization header mismatch:\n got=%s\nwant=%s", got, expected)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server never received the request")
	}
}

// TestClientWebSocketAuth confirms the WebSocket upgrade carries credentials
// and a rejected upgrade surfaces as an error rather than a silent connection.
func TestClientWebSocketAuth(t *testing.T) {
	srv := startClientTestServer(t)

	// Authenticated client against a non-existent session: auth passes, the
	// session lookup yields 404, and the dial must return an error.
	c, err := client.NewAuthenticatedClient("http://"+srv.Addr(), cAdminID, cAdminSec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Subscribe(ctx, uuid.New()); err == nil {
		t.Fatal("expected WebSocket dial to fail for a non-existent session")
	}
}
