// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the Apache 2 LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
)

type ctxKey int

const principalCtxKey ctxKey = iota

// ErrorResponse mirrors the server package's error body so that
// authentication failures keep the existing response shape and only add a
// status code plus error detail.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
	Code    int    `json:"code"`
}

// Middleware enforces authentication on protected control-plane endpoints.
type Middleware struct {
	store    *Store
	openMode bool
	log      *slog.Logger
}

// NewMiddleware constructs the authentication middleware. When openMode is
// true the process bound a loopback address without any credential material;
// loopback callers are then trusted without credentials (with the startup
// warning emitted by the server). Every non-loopback request is rejected even
// in open mode.
func NewMiddleware(store *Store, openMode bool, log *slog.Logger) *Middleware {
	return &Middleware{store: store, openMode: openMode, log: log}
}

// PrincipalFromContext returns the authenticated principal attached to the
// request context, or nil.
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalCtxKey).(*Principal)
	return p
}

// Wrap returns an http.Handler that authenticates every request before
// delegating to next.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		source := clientSource(r)

		// Open mode is the narrowly scoped loopback fallback that preserves
		// the historic local, credential-free CLI workflow.
		if m.openMode && isLoopbackRemote(r) {
			// A local superuser principal: writable and unrestricted, but
			// never derived from any presented secret.
			p := localPrincipal()
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey, p)))
			return
		}

		keyID, secret, ok := r.BasicAuth()
		if !ok {
			m.deny(w, r, source, "", ErrMissing, http.StatusUnauthorized)
			return
		}

		principal, err := m.store.Authenticate(source, keyID, secret)
		if err != nil {
			reason := reasonOf(err)
			status := http.StatusUnauthorized
			if reason == ReasonThrottled {
				status = http.StatusTooManyRequests
			}
			m.deny(w, r, source, keyID, err, status)
			return
		}

		// Read-only credentials must never reach a mutating endpoint.
		if !principal.CanWrite() && isWriteMethod(r.Method) {
			m.deny(w, r, source, keyID, ErrForbidden, http.StatusForbidden)
			return
		}

		// Audit the success using only the irreversible fingerprint.
		m.log.Info("authenticated request",
			"principal", m.store.Fingerprint(keyID),
			"source", source,
			"method", r.Method,
			"path", r.URL.Path)

		ctx := context.WithValue(r.Context(), principalCtxKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *Middleware) deny(w http.ResponseWriter, r *http.Request, source, keyID string, err error, status int) {
	reason := reasonOf(err)

	// The audit record contains the failure category and an irreversible
	// identifier only. Credentials never appear in logs.
	attrs := []slog.Attr{
		slog.String("source", source),
		slog.String("reason", reason.String()),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if keyID != "" {
		attrs = append(attrs, slog.String("principal", m.store.Fingerprint(keyID)))
	}
	m.log.LogAttrs(r.Context(), slog.LevelWarn, "authentication failed", attrs...)

	w.Header().Set("WWW-Authenticate", `Basic realm="amass-engine"`)
	writeAuthError(w, status, statusText(status))
}

func statusText(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "authentication required"
	case http.StatusForbidden:
		return "credential is not permitted to perform this action"
	case http.StatusTooManyRequests:
		return "too many authentication failures; try again later"
	default:
		return "request denied"
	}
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: msg, Code: status})
}

// clientSource extracts the direct peer IP address for throttling and
// auditing. Forwarded headers are intentionally ignored because they are
// trivially spoofable.
func clientSource(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopbackRemote(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost"
}

// IsLoopbackAddr reports whether the listen address binds exclusively to a
// loopback interface. An empty host or the wildcard ":port" form binds every
// interface and therefore is not loopback.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Addresses without a port (e.g. "127.0.0.1") are still usable.
		host = addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func isWriteMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// localPrincipal builds the implicit principal used in loopback open mode.
func localPrincipal() *Principal {
	return &Principal{KeyID: "local-loopback", readOnly: false}
}
