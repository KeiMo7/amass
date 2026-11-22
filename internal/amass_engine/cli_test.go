// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass_engine

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFlagset(t *testing.T) {
	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse([]string{"-nocolor", "-silent", "-log-dir", "/tmp/logs"}); err != nil {
		t.Fatal(err)
	}
	if !args.Options.NoColor || !args.Options.Silent || args.Filepaths.LogDir != "/tmp/logs" || args.Help {
		t.Errorf("args = %+v", args)
	}
	if err := fs.Parse([]string{"-nosuchflag"}); err == nil {
		t.Error("an unknown flag was accepted")
	}
}

func TestSelectLoggerWritesToTheLogDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	l, err := selectLogger(dir)
	if err != nil || l == nil {
		t.Fatalf("selectLogger = %v, %v", l, err)
	}
	l.Info("engine started")

	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "amass_engine_") {
		t.Fatalf("log directory = %v, %v", entries, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil || !strings.Contains(string(data), "engine started") {
		t.Errorf("log file = %q, %v", data, err)
	}
}
