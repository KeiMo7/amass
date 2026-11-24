// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "net/http/pprof"

	"github.com/owasp-amass/amass/v5/engine/api/server"
	"github.com/owasp-amass/amass/v5/engine/dispatcher"
	"github.com/owasp-amass/amass/v5/engine/plugins"
	"github.com/owasp-amass/amass/v5/engine/registry"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// Environment variables consumed by the engine control plane at startup.
const (
	// EnvEngineAddr sets the control-plane listen address (default ":4000").
	EnvEngineAddr = "AMASS_ENGINE_ADDR"
	// EnvEngineCreds points at the YAML credential file. When unset the
	// server runs in loopback-only open mode and refuses non-loopback binds.
	EnvEngineCreds = "AMASS_ENGINE_CREDENTIALS"
)

type Engine struct {
	Log        *slog.Logger
	Dispatcher et.Dispatcher
	Registry   et.Registry
	Manager    et.SessionManager
	Server     *server.Server
}

func NewEngine(l *slog.Logger) (*Engine, error) {
	go func() {
		_ = http.ListenAndServe("127.0.0.1:6060", nil)
	}()

	if l == nil {
		l = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}

	reg := registry.NewRegistry(l)
	mgr := sessions.NewManager(l, reg)
	if mgr == nil {
		return nil, errors.New("failed to create the session manager")
	}

	dis := dispatcher.NewDispatcher(l, reg, mgr)
	if err := plugins.LoadAndStartPlugins(reg); err != nil {
		return nil, err
	}

	srvCfg := server.Config{
		Addr:           os.Getenv(EnvEngineAddr),
		CredentialFile: os.Getenv(EnvEngineCreds),
	}
	srv, err := server.NewServer(l, dis, mgr, srvCfg)
	if err != nil || srv == nil {
		dis.Shutdown()
		mgr.Shutdown()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to create the API server")
	}

	ch := make(chan error, 1)
	go func(errch chan error) { errch <- srv.Start() }(ch)

	t := time.NewTimer(3 * time.Second)
	defer t.Stop()

	select {
	case err := <-ch:
		if err != nil {
			_ = srv.Shutdown()
			dis.Shutdown()
			mgr.Shutdown()
			return nil, err
		}
	case <-t.C:
		// If the server does not return an error within 3 seconds, we assume it started successfully
	}

	return &Engine{
		Log:        l,
		Dispatcher: dis,
		Registry:   reg,
		Manager:    mgr,
		Server:     srv,
	}, nil
}

func (e *Engine) Shutdown() {
	_ = e.Server.Shutdown()
	e.Dispatcher.Shutdown()
	e.Manager.Shutdown()
}
