// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/engine/api/auth"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// defaultAccessCheckInterval bounds how quickly a WebSocket notices an
// expired credential or a terminated session without an explicit revocation
// event.
const defaultAccessCheckInterval = 10 * time.Second

// WSLogsHandler godoc
//
// @Summary      Stream session logs (WebSocket)
// @Description  Upgrades the HTTP connection to a WebSocket and streams session log lines as UTF-8 text frames.
// @Description  The server sends periodic ping frames (~30s) and expects pong responses; idle connections may be closed.
// @Description  The connection requires the same credentials as the session's HTTP endpoints and is closed if the credential expires, is revoked, or loses access to the session.
// @Tags         sessions
// @Param        session_token  path  string  true  "Session token (UUID)"
// @Success      101  "Switching Protocols (WebSocket upgrade)"
// @Failure      400  {object}  ErrorResponse  "Invalid session token"
// @Failure      401  {object}  ErrorResponse  "Authentication required"
// @Failure      404  {object}  ErrorResponse  "Session not found"
// @Security     BasicAuth
// @Router       /sessions/{session_token}/ws/logs [get]
// @Header  	 101  {string}  Upgrade     "websocket"
// @Header  	 101  {string}  Connection  "Upgrade"
func (v *V1Handlers) WSLogsHandler(w http.ResponseWriter, r *http.Request) {
	sess, ok := v.authorizeSession(w, r)
	if !ok {
		return
	}

	principal := auth.PrincipalFromContext(r.Context())

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade failed: %v", err)
		return
	}

	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Revocation and expiry are signalled through the store's watcher. The
	// connection is torn down as soon as the principal no longer validates.
	revCh := v.store.RevocationChannel()
	// The request context is cancelled as soon as this handler returns, so it
	// must not govern the lifetime of the upgraded connection. The handler's
	// long-lived context is used instead.
	// A single write mutex serializes the two goroutines: gorilla/websocket
	// permits at most one concurrent writer per connection.
	var writeMu sync.Mutex
	go v.watchAccess(v.ctx, conn, &writeMu, principal, sess.ID(), revCh)
	go writeLoop(conn, &writeMu, sess.PubSub().Subscribe())
	v.log.Info("connected to session log stream",
		"principal", v.store.Fingerprint(principal.KeyID))
}

// watchAccess closes the WebSocket when the credential is revoked/expired, the
// session leaves the principal's scope, or the underlying session is
// terminated.
func (v *V1Handlers) watchAccess(ctx context.Context, conn *websocket.Conn, writeMu *sync.Mutex, p *auth.Principal, sessionID uuid.UUID, revCh <-chan struct{}) {
	ticker := time.NewTicker(v.accessCheckInterval)
	defer ticker.Stop()

	closeConn := func(reason string) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, reason),
			time.Now().Add(5*time.Second),
		)
		_ = conn.Close()
	}

	for {
		select {
		case <-ctx.Done():
			closeConn("server shutting down")
			return
		case <-revCh:
			// A new revocation generation arrived; re-subscribe and validate.
			revCh = v.store.RevocationChannel()
			if v.store.IsRevoked(p.KeyID) || !p.CanAccessSession(sessionID) {
				v.log.Warn("closing log stream: credential revoked or out of scope",
					"principal", v.store.Fingerprint(p.KeyID))
				closeConn("credential revoked")
				return
			}
		case <-ticker.C:
			// Periodic re-validation covers expiry without an explicit
			// revocation event.
			if v.store.IsRevoked(p.KeyID) || !p.CanAccessSession(sessionID) {
				v.log.Warn("closing log stream: credential no longer valid",
					"principal", v.store.Fingerprint(p.KeyID))
				closeConn("credential expired")
				return
			}
			if v.mgr.GetSession(sessionID) == nil {
				closeConn("session terminated")
				return
			}
		}
	}
}

func writeLoop(conn *websocket.Conn, writeMu *sync.Mutex, ch <-chan *string) {
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()

	for {
		select {
		case msg, ok := <-ch:
			writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				writeMu.Unlock()
				return
			}
			err := conn.WriteMessage(websocket.TextMessage, []byte(*msg))
			writeMu.Unlock()
			if err != nil {
				return
			}
		case <-ping.C:
			writeMu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := conn.WriteMessage(websocket.PingMessage, nil)
			writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}
