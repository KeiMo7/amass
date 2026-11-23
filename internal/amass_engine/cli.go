// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package amass_engine

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine"
	"github.com/owasp-amass/amass/v5/internal/afmt"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

const (
	UsageMsg    = "[options] [-log-dir path]"
	Description = "Run the Amass collection engine to populate the OAM database"
)

// ResolverQPSEnv sets the queries per second sent to each DNS resolver when
// the -resolver-qps flag is not given.
const ResolverQPSEnv = "AMASS_RESOLVER_QPS"

// InterfaceEnv names the network interface the engine's traffic leaves
// through when the -iface flag is not given.
const InterfaceEnv = "AMASS_IFACE"

type Args struct {
	Help    bool
	Options struct {
		NoColor     bool
		Silent      bool
		ResolverQPS int
		Interface   string
	}
	Filepaths struct {
		LogDir string
	}
}

func NewFlagset(args *Args, errorHandling flag.ErrorHandling) *flag.FlagSet {
	fs := flag.NewFlagSet("engine", errorHandling)

	fs.BoolVar(&args.Help, "h", false, "Show the program usage message")
	fs.BoolVar(&args.Help, "help", false, "Show the program usage message")
	fs.BoolVar(&args.Options.NoColor, "nocolor", false, "Disable colorized output")
	fs.BoolVar(&args.Options.Silent, "silent", false, "Disable all output during execution")
	fs.StringVar(&args.Filepaths.LogDir, "log-dir", "", "path to the log directory")
	fs.IntVar(&args.Options.ResolverQPS, "resolver-qps", -1, fmt.Sprintf("Queries per second sent to each "+
		"DNS resolver, across all enumerations; 0 for no limit (default %d, or $%s)",
		amassdns.DefaultResolverQPS, ResolverQPSEnv))
	fs.StringVar(&args.Options.Interface, "iface", "", fmt.Sprintf("Network interface (name or IP address) "+
		"the engine's traffic leaves through, unless an enumeration names its own (default $%s)", InterfaceEnv))
	return fs
}

func CLIWorkflow(cmdName string, clArgs []string) {
	var args Args
	fs := NewFlagset(&args, flag.ContinueOnError)

	engineBuf := new(bytes.Buffer)
	fs.SetOutput(engineBuf)

	var usage = func() {
		afmt.PrintBanner()
		_, _ = afmt.G.Fprintf(color.Error, "Usage: %s %s\n\n", cmdName, UsageMsg)

		if args.Help {
			fs.PrintDefaults()
			_, _ = afmt.G.Fprintln(color.Error, engineBuf.String())
			return
		}

		_, _ = afmt.G.Fprintln(color.Error, "Use the -h or --help flag to see the flags and default values")
		_, _ = afmt.G.Fprintf(color.Error, "\nThe Amass Discord server can be found here: %s\n\n", afmt.DiscordInvitation)
	}

	if err := fs.Parse(clArgs); err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	if args.Help {
		usage()
		return
	}
	if args.Options.NoColor {
		color.NoColor = true
	}
	if args.Options.Silent {
		color.Output = io.Discard
		color.Error = io.Discard
	}

	qps, err := resolverQPS(args.Options.ResolverQPS, os.LookupEnv)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	amassdns.SetResolverQPS(qps)

	local, err := engineInterface(args.Options.Interface, os.LookupEnv)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "%v\n", err)
		os.Exit(1)
	}
	amassnet.SetLocalAddrs(local)

	l, err := selectLogger(args.Filepaths.LogDir)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to create the logger: %v", err)
		os.Exit(1)
	}

	e, err := engine.NewEngine(l)
	if err != nil {
		_, _ = afmt.R.Fprintf(color.Error, "Failed to start the engine: %v", err)
		os.Exit(1)
	}
	defer e.Shutdown()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(quit)
	<-quit
	l.Info("Terminating the collection engine")
}

// resolverQPS returns the engine's limit on queries per second per DNS
// resolver: the flag when given (zero or more), else the environment
// variable, else the default.
func resolverQPS(flagValue int, lookup func(string) (string, bool)) (int, error) {
	if flagValue >= 0 {
		return flagValue, nil
	}
	if v, ok := lookup(ResolverQPSEnv); ok && strings.TrimSpace(v) != "" {
		qps, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil || qps < 0 {
			return 0, fmt.Errorf("%s must be a whole number of queries per second, not %q", ResolverQPSEnv, v)
		}
		return qps, nil
	}
	return amassdns.DefaultResolverQPS, nil
}

// engineInterface returns the local addresses of the engine's network
// interface: the flag's when given, else the environment variable's, else
// the zero LocalAddrs, which leaves the choice to the system.
func engineInterface(flagValue string, lookup func(string) (string, bool)) (amassnet.LocalAddrs, error) {
	spec := strings.TrimSpace(flagValue)
	if spec == "" {
		if v, ok := lookup(InterfaceEnv); ok {
			spec = strings.TrimSpace(v)
		}
	}

	local, err := amassnet.InterfaceAddrs(spec)
	if err != nil {
		return amassnet.LocalAddrs{}, fmt.Errorf("the engine's network interface: %w", err)
	}
	return local, nil
}

func selectLogger(dir string) (*slog.Logger, error) {
	filename := fmt.Sprintf("amass_engine_%s.log", time.Now().Format("2006-01-02T15:04:05"))

	if dir != "" {
		return tools.NewFileLogger(dir, filename)
	}
	if l, err := tools.NewSyslogLogger(); err == nil && l != nil {
		return l, nil
	}

	dir = config.OutputDirectory("")
	if l, err := tools.NewFileLogger(dir, filename); err == nil && l != nil {
		return l, nil
	}

	return slog.New(slog.NewTextHandler(os.Stdout, nil)), nil
}
