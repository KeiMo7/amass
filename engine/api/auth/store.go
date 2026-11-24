// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the Apache 2 LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// credentialEntry is the in-memory representation of a credential. The raw
// secret is never retained: only its SHA-256 digest is stored.
type credentialEntry struct {
	keyID     string
	secret    [sha256.Size]byte
	expiresAt time.Time
	sessions  map[uuid.UUID]struct{}
	readOnly  bool
	revoked   bool
	// fingerprint is an irreversible identifier derived from the key ID and
	// the secret digest. It is safe to write to logs and audit records.
	fingerprint string
}

// Store is a thread-safe in-memory credential store.
type Store struct {
	mu sync.RWMutex

	creds map[string]*credentialEntry

	// rev is closed whenever a credential is revoked so that long-lived
	// connections can re-evaluate their access.
	revMu    sync.Mutex
	rev      chan struct{}
	watchers int

	// throttle tracks consecutive authentication failures per source. A
	// successful authentication clears the counter for that source.
	throttleMu     sync.Mutex
	failures       map[string]int
	maxFailures    int
	failureWindow  time.Duration
	firstFailureAt map[string]time.Time

	now func() time.Time
}

// Option configures a Store at construction.
type Option func(*Store)

// WithFailureWindow overrides the rolling window used by the throttling
// logic. It exists primarily so tests can exercise throttling deterministically.
func WithFailureWindow(d time.Duration) Option {
	return func(s *Store) { s.failureWindow = d }
}

// WithMaxFailures overrides the number of consecutive failures tolerated from
// a single source before it is throttled.
func WithMaxFailures(n int) Option {
	return func(s *Store) { s.maxFailures = n }
}

// WithClock injects a custom clock. It is primarily used by tests that need
// to exercise credential expiry deterministically.
func WithClock(f func() time.Time) Option {
	return func(s *Store) { s.now = f }
}

// NewStore builds an empty store. An empty store running without an open-mode
// exemption authenticates nobody, which is the desired fail-closed default.
func NewStore(opts ...Option) *Store {
	s := &Store{
		creds:          make(map[string]*credentialEntry),
		rev:            make(chan struct{}),
		failures:       make(map[string]int),
		firstFailureAt: make(map[string]time.Time),
		maxFailures:    defaultMaxFailures,
		failureWindow:  defaultFailureWindow,
		now:            time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

const (
	defaultMaxFailures   = 5
	defaultFailureWindow = 10 * time.Minute
)

// LoadFile parses the credential file at path and replaces every credential
// currently held by the store. Existing watchers continue to work.
func (s *Store) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading credential file: %w", err)
	}

	var f CredentialFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parsing credential file: %w", err)
	}
	return s.Replace(f.Credentials)
}

// Replace swaps in the provided credential set.
func (s *Store) Replace(in []Credential) error {
	if len(in) == 0 {
		return errors.New("credential file contains no credentials")
	}

	entries := make(map[string]*credentialEntry, len(in))
	for _, c := range in {
		if c.KeyID == "" {
			return errors.New("credential is missing an id")
		}
		if len(c.Secret) < MinimumSecretLen {
			return fmt.Errorf("credential %q secret must be at least %d bytes", c.KeyID, MinimumSecretLen)
		}
		if _, dup := entries[c.KeyID]; dup {
			return fmt.Errorf("duplicate credential id %q", c.KeyID)
		}

		e := &credentialEntry{
			keyID:       c.KeyID,
			secret:      sha256.Sum256([]byte(c.Secret)),
			expiresAt:   c.ExpiresAt,
			readOnly:    c.ReadOnly,
			fingerprint: fingerprint(c.KeyID, sha256.Sum256([]byte(c.Secret))),
		}
		if len(c.Sessions) > 0 {
			e.sessions = make(map[uuid.UUID]struct{}, len(c.Sessions))
			for _, id := range c.Sessions {
				e.sessions[id] = struct{}{}
			}
		}
		entries[c.KeyID] = e
	}

	s.mu.Lock()
	s.creds = entries
	s.mu.Unlock()
	return nil
}

// Empty reports whether the store holds any credential material.
func (s *Store) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds) == 0
}

// Authenticate validates the presented key ID and secret on behalf of the
// named source (typically a client IP address used for throttling).
//
// The comparison is constant time and every rejection path performs the same
// amount of work so that response timing cannot reveal whether a key ID exists.
func (s *Store) Authenticate(source, keyID, secret string) (*Principal, error) {
	if s.throttled(source) {
		return nil, ErrThrottled
	}

	// A throwaway digest guarantees that an unknown key ID still performs a
	// real constant-time comparison instead of an early return.
	probe := sha256.Sum256([]byte(secret))

	// Snapshot the entry (if any) while holding the read lock; all further
	// work happens without the lock held.
	var snapshot credentialEntry
	var found bool

	s.mu.RLock()
	var entry *credentialEntry
	if entry, found = s.creds[keyID]; found {
		snapshot = *entry
	}
	s.mu.RUnlock()

	if !found {
		// Compare against a freshly random digest so the workload does not
		// depend on whether the key ID exists.
		var bogus [sha256.Size]byte
		_, _ = rand.Read(bogus[:])
		subtle.ConstantTimeCompare(probe[:], bogus[:])
		s.recordFailure(source)
		return nil, ErrForged
	}

	if subtle.ConstantTimeCompare(probe[:], snapshot.secret[:]) != 1 {
		s.recordFailure(source)
		return nil, ErrForged
	}
	if !snapshot.expiresAt.IsZero() && !s.now().Before(snapshot.expiresAt) {
		s.recordFailure(source)
		return nil, ErrExpired
	}
	if snapshot.revoked {
		s.recordFailure(source)
		return nil, ErrRevoked
	}

	// Successful authentication resets the source's failure counter, so
	// throttling never affects legitimate callers.
	s.resetFailures(source)

	var sessions map[uuid.UUID]struct{}
	if len(snapshot.sessions) > 0 {
		sessions = make(map[uuid.UUID]struct{}, len(snapshot.sessions))
		for id := range snapshot.sessions {
			sessions[id] = struct{}{}
		}
	}
	return &Principal{
		KeyID:    snapshot.keyID,
		readOnly: snapshot.readOnly,
		sessions: sessions,
	}, nil
}

// Revoke marks the credential with the given key ID as revoked and signals
// every watcher. Revoking an unknown ID is not an error so that callers do not
// have to distinguish "already gone" from "just revoked".
func (s *Store) Revoke(keyID string) error {
	s.mu.Lock()
	entry, ok := s.creds[keyID]
	if ok {
		entry.revoked = true
	}
	s.mu.Unlock()

	s.broadcast()
	if !ok {
		return fmt.Errorf("credential %q not found", keyID)
	}
	return nil
}

// IsRevoked reports whether the key ID is currently revoked. Unknown IDs are
// treated as revoked because they are not valid credentials.
func (s *Store) IsRevoked(keyID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.creds[keyID]
	if !ok {
		return true
	}
	return entry.revoked || (!entry.expiresAt.IsZero() && !s.now().Before(entry.expiresAt))
}

// Fingerprint returns the irreversible log identifier for a key ID. It never
// returns secret material.
func (s *Store) Fingerprint(keyID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if entry, ok := s.creds[keyID]; ok {
		return entry.fingerprint
	}
	return "unknown:" + shortHash(keyID)
}

// RevocationChannel returns a channel that is closed whenever any credential
// is revoked. Long-lived connections select on it and re-validate their
// principal; the store allocates a fresh channel for the next generation.
func (s *Store) RevocationChannel() <-chan struct{} {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	s.watchers++
	return s.rev
}

func (s *Store) broadcast() {
	s.revMu.Lock()
	defer s.revMu.Unlock()
	close(s.rev)
	s.rev = make(chan struct{})
}

// fingerprint derives an irreversible identifier from the key ID and the
// stored secret digest. The raw secret is unavailable here by design.
func fingerprint(keyID string, digest [sha256.Size]byte) string {
	h := sha256.New()
	h.Write([]byte(keyID))
	h.Write(digest[:])
	return "fp_" + hex.EncodeToString(h.Sum(nil))[:16]
}

// shortHash is used for identifiers that must not echo a raw key ID into the
// logs when the credential is no longer known to the store.
func shortHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}

// throttled reports whether the source is currently locked out. Counters age
// out of the rolling window automatically.
func (s *Store) throttled(source string) bool {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()

	first, seen := s.firstFailureAt[source]
	if !seen {
		return false
	}
	if s.now().Sub(first) > s.failureWindow {
		delete(s.failures, source)
		delete(s.firstFailureAt, source)
		return false
	}
	return s.failures[source] >= s.maxFailures
}

func (s *Store) recordFailure(source string) {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()

	if _, seen := s.firstFailureAt[source]; !seen {
		s.firstFailureAt[source] = s.now()
	}
	s.failures[source]++
}

func (s *Store) resetFailures(source string) {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	delete(s.failures, source)
	delete(s.firstFailureAt, source)
}

// Failures returns the current consecutive failure count for a source. It is
// used by tests and operational diagnostics.
func (s *Store) Failures(source string) int {
	s.throttleMu.Lock()
	defer s.throttleMu.Unlock()
	return s.failures[source]
}
