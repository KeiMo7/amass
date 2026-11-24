// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/owasp-amass/amass/v5/engine/api/auth"
	v1 "github.com/owasp-amass/amass/v5/engine/api/server/v1"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

const DefaultAddr = ":4000"

type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
	Code    int    `json:"code"`
}

// Config holds the settings required to construct an authenticated engine
// control-plane server.
type Config struct {
	// Addr is the TCP listen address, e.g. ":4000" or "127.0.0.1:4000".
	Addr string
	// CredentialFile is the path to the YAML credential store. When empty the
	// server has no key material and must apply the open-mode restrictions.
	CredentialFile string
	// WSCheckInterval bounds how quickly a log stream notices an expired
	// credential or terminated session without an explicit event. Zero keeps
	// the package default. It is mainly used by tests.
	WSCheckInterval time.Duration
	// AuthOptions tune the credential store (used by tests).
	AuthOptions []auth.Option
	// Clock optionally overrides the store's time source. It exists for
	// deterministic expiry tests; production code leaves it nil.
	Clock func() time.Time
}

type Server struct {
	ctx     context.Context
	cancel  context.CancelFunc
	log     *slog.Logger
	dis     et.Dispatcher
	mgr     et.SessionManager
	ch      chan struct{}
	started chan struct{}
	srv     *http.Server
	ln      net.Listener
	apiV1   *v1.V1Handlers
	auth    *auth.Store
	mw      *auth.Middleware
	open    bool
}

// NewServer constructs the control-plane server. It enforces the key-material
// policy up front: without credentials the process may only bind a loopback
// address (with an explicit warning); binding a non-loopback address is a
// hard startup failure.
func NewServer(logger *slog.Logger, d et.Dispatcher, mgr et.SessionManager, cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}

	storeOpts := cfg.AuthOptions
	if cfg.Clock != nil {
		storeOpts = append(storeOpts, auth.WithClock(cfg.Clock))
	}
	store := auth.NewStore(storeOpts...)
	openMode := false

	if cfg.CredentialFile == "" {
		if !auth.IsLoopbackAddr(cfg.Addr) {
			return nil, errors.New("refusing to start: no credential material configured and the listen address is not loopback; provide a credential file or bind 127.0.0.1")
		}
		openMode = true
	} else {
		if err := store.LoadFile(cfg.CredentialFile); err != nil {
			return nil, err
		}
	}

	r := mux.NewRouter()
	ctx, cancel := context.WithCancel(context.Background())

	apiV1, err := v1.NewV1Handlers(ctx, d, mgr, store, logger)
	if err != nil {
		cancel()
		return nil, err
	}

	mw := auth.NewMiddleware(store, openMode, logger)
	if cfg.WSCheckInterval > 0 {
		apiV1.SetAccessCheckInterval(cfg.WSCheckInterval)
	}

	srv := &Server{
		ctx:     ctx,
		cancel:  cancel,
		log:     logger,
		dis:     d,
		mgr:     mgr,
		ch:      make(chan struct{}),
		started: make(chan struct{}),
		srv: &http.Server{
			Addr:         cfg.Addr,
			Handler:      r,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		apiV1: apiV1,
		auth:  store,
		mw:    mw,
		open:  openMode,
	}

	if openMode {
		logger.Warn("ENGINE CONTROL PLANE IS RUNNING IN OPEN MODE: no credential material was configured; access is restricted to loopback clients and every non-loopback request will be rejected")
	}

	// Bind immediately so that an unusable address fails at construction
	// time rather than asynchronously inside Start.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		cancel()
		return nil, err
	}
	srv.ln = ln

	srv.routes(r, mw)
	return srv, nil
}

// Addr returns the address the server is actually listening on. It is useful
// when tests bind port zero.
func (s *Server) Addr() string {
	if s.ln == nil {
		return s.srv.Addr
	}
	return s.ln.Addr().String()
}

// AuthStore exposes the credential store so operational tooling (and tests)
// can revoke credentials at runtime.
func (s *Server) AuthStore() *auth.Store {
	return s.auth
}

func (s *Server) Start() error {
	close(s.started)
	s.log.Info("Server listening on", "addr", s.Addr(), "open_mode", s.open)
	err := s.srv.Serve(s.ln)

	s.cancel()
	close(s.ch)
	return err
}

func (s *Server) Shutdown() error {
	// If Start was never invoked (e.g. startup-policy tests), there is
	// nothing serving and the completion channel would never close.
	select {
	case <-s.started:
	default:
		s.cancel()
		close(s.ch)
		if s.ln != nil {
			_ = s.ln.Close()
		}
		return nil
	}

	err := s.srv.Shutdown(s.ctx)
	<-s.ch
	return err
}

// UUID route regex (common RFC 4122 form)
const uuidRE = `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`

// Asset type route regex (tighten if you have an enum)
const assetTypeRE = `[a-z0-9][a-z0-9_-]{0,63}`

/*
Routes (v1)

GET    /api/v1/health                         (public, stateless)
POST   /api/v1/sessions                       (authenticated, write)
GET	   /api/v1/sessions/list                  (authenticated, read)
DELETE /api/v1/sessions/{session_token}       (authenticated, write, session-scoped)
GET    /api/v1/sessions/{session_token}/stats (authenticated, read, session-scoped)
GET    /api/v1/sessions/{session_token}/scope/{asset_type}        (authenticated, read, session-scoped)
POST   /api/v1/sessions/{session_token}/assets/{asset_type}       (authenticated, write, session-scoped)
POST   /api/v1/sessions/{session_token}/assets/{asset_type}:bulk  (authenticated, write, session-scoped)
GET    /api/v1/sessions/{session_token}/ws/logs                   (authenticated, read, session-scoped)
*/
func (s *Server) routes(r *mux.Router, mw *auth.Middleware) {
	r.Use(s.loggingMiddleware)

	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "route not found", nil)
	})
	r.MethodNotAllowedHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed", nil)
	})

	v1 := r.PathPrefix("/api/v1").Subrouter()
	// The health probe is the only explicitly public endpoint. It returns no
	// session or asset information.
	v1.HandleFunc("/health", s.apiV1.HealthCheck).Methods(http.MethodGet)

	// Every other endpoint is behind the authentication middleware.
	protected := v1.PathPrefix("").Subrouter()
	protected.Use(mw.Wrap)

	sessions := protected.PathPrefix("/sessions").Subrouter()
	sessions.HandleFunc("", s.apiV1.CreateSessionHandler).Methods(http.MethodPost)
	sessions.HandleFunc("/list", s.apiV1.ListSessionsHandler).Methods(http.MethodGet)

	session := sessions.PathPrefix("/{session_token:" + uuidRE + "}").Subrouter()
	session.HandleFunc("", s.apiV1.TerminateSessionHandler).Methods(http.MethodDelete)
	session.HandleFunc("/stats", s.apiV1.GetStatsHandler).Methods(http.MethodGet)

	scope := session.PathPrefix("/scope").Subrouter()
	scope.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.apiV1.GetScopeHandler).Methods(http.MethodGet)

	assets := session.PathPrefix("/assets").Subrouter()
	// Single add: type in path (since OAM payload does not include it)
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}", s.apiV1.AddAssetTypedHandler).Methods(http.MethodPost)
	// Bulk add: :bulk suffix
	assets.HandleFunc("/{asset_type:"+assetTypeRE+"}:bulk", s.apiV1.AddAssetsBulkHandler).Methods(http.MethodPost)

	// WebSocket logs only
	ws := session.PathPrefix("/ws").Subrouter()
	ws.HandleFunc("/logs", s.apiV1.WSLogsHandler).Methods(http.MethodGet)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// The Authorization header is deliberately never logged; the
		// authentication middleware records only irreversible fingerprints.
		next.ServeHTTP(w, r)
		s.log.Info("request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string, err error) {
	out := ErrorResponse{Error: msg, Code: status}
	if err != nil {
		out.Details = err.Error()
	}
	writeJSON(w, status, out)
}
