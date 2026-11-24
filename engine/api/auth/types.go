// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the Apache 2 LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package auth provides credential-based authentication and authorization
// primitives for the engine control plane.
//
// Credentials are never stored or compared in plaintext form: each secret is
// held only as a SHA-256 digest and compared using constant-time operations.
// Credentials may be scoped to a fixed set of sessions, may be read-only, may
// carry an expiry time and may be revoked at runtime. Revocation and expiry
// events are exposed through watchers so long-lived connections (e.g. the
// real-time log WebSocket) can terminate promptly.
package auth

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// MinimumSecretLen is the minimum accepted length, in bytes, of a credential
// secret. Short secrets make brute force against the control plane practical
// and are therefore rejected when the credential file is loaded.
const MinimumSecretLen = 16

// Credential models a single entry in the credential file.
type Credential struct {
	// KeyID identifies the credential (the HTTP Basic Auth username).
	KeyID string `yaml:"id"`
	// Secret is the shared secret (the HTTP Basic Auth password). It is only
	// ever present while the file is being parsed; the store keeps only its
	// digest.
	Secret string `yaml:"secret"`
	// ExpiresAt, when non-zero, marks the instant after which the credential
	// is no longer accepted.
	ExpiresAt time.Time `yaml:"expiresAt,omitempty"`
	// Sessions optionally restricts the credential to this exact set of
	// session identifiers. An empty slice grants access to every session.
	Sessions []uuid.UUID `yaml:"sessions,omitempty"`
	// ReadOnly marks a credential that may perform read requests but never
	// create sessions, add assets or terminate tasks.
	ReadOnly bool `yaml:"readOnly,omitempty"`
}

// CredentialFile is the on-disk YAML representation of the credential store.
type CredentialFile struct {
	Credentials []Credential `yaml:"credentials"`
}

// Principal is the authenticated identity attached to a request after
// successful authentication. It contains no secret material.
type Principal struct {
	// KeyID is the presented credential identifier.
	KeyID string
	// readOnly mirrors the credential's role.
	readOnly bool
	// sessions is the (possibly empty) set of sessions the credential may
	// access. An empty map means "all sessions".
	sessions map[uuid.UUID]struct{}
}

// CanWrite reports whether the principal is allowed to perform mutating
// requests.
func (p *Principal) CanWrite() bool {
	return p != nil && !p.readOnly
}

// CanAccessSession reports whether the principal may access the provided
// session identifier. Credentials without a session restriction may access
// every session.
func (p *Principal) CanAccessSession(id uuid.UUID) bool {
	if p == nil {
		return false
	}
	if len(p.sessions) == 0 {
		return true
	}
	_, ok := p.sessions[id]
	return ok
}

// VisibleSessions filters the provided session identifiers down to those the
// principal may access.
func (p *Principal) VisibleSessions(ids []uuid.UUID) []uuid.UUID {
	if p == nil {
		return ids
	}
	if len(p.sessions) == 0 {
		return ids
	}
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if _, ok := p.sessions[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

// FailureReason classifies an authentication failure for internal accounting
// and auditing. The external HTTP response deliberately does not expose the
// category.
type FailureReason int

const (
	ReasonMissing FailureReason = iota
	ReasonForged
	ReasonExpired
	ReasonRevoked
	ReasonThrottled
	ReasonForbidden
	ReasonInternal
)

// String returns a stable, secret-free label for the failure category.
func (r FailureReason) String() string {
	switch r {
	case ReasonMissing:
		return "missing"
	case ReasonForged:
		return "forged"
	case ReasonExpired:
		return "expired"
	case ReasonRevoked:
		return "revoked"
	case ReasonThrottled:
		return "throttled"
	case ReasonForbidden:
		return "forbidden"
	default:
		return "internal"
	}
}

// AuthError is the typed error returned by the authentication layer. It never
// embeds credential material.
type AuthError struct {
	Reason FailureReason
}

func (e *AuthError) Error() string {
	return "authentication failed: " + e.Reason.String()
}

// Sentinel forms of the typed error for callers that use errors.Is.
var (
	ErrMissing   = &AuthError{Reason: ReasonMissing}
	ErrForged    = &AuthError{Reason: ReasonForged}
	ErrExpired   = &AuthError{Reason: ReasonExpired}
	ErrRevoked   = &AuthError{Reason: ReasonRevoked}
	ErrThrottled = &AuthError{Reason: ReasonThrottled}
	ErrForbidden = &AuthError{Reason: ReasonForbidden}
	ErrInternal  = &AuthError{Reason: ReasonInternal}
)

// reasonOf extracts the FailureReason from an auth error. Any non-auth error
// is classified as an internal failure so the request is denied.
func reasonOf(err error) FailureReason {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae.Reason
	}
	return ReasonInternal
}
