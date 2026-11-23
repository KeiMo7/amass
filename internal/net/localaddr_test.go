// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestInterfaceAddr(t *testing.T) {
	if a, err := InterfaceAddr(" "); err != nil || a.IsValid() {
		t.Errorf("InterfaceAddr(\"\") = %v, %v; want the zero Addr", a, err)
	}
	if a, err := InterfaceAddr("127.0.0.1"); err != nil || a != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("InterfaceAddr(127.0.0.1) = %v, %v", a, err)
	}
	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	if _, err := InterfaceAddr("192.0.2.1"); err == nil {
		t.Error("an address on no interface was accepted")
	}
	if _, err := InterfaceAddr("no-such-iface0"); err == nil {
		t.Error("a missing interface was accepted")
	}

	ifcs, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces: %v", err)
	}
	for _, ifc := range ifcs {
		if ifc.Flags&net.FlagLoopback != 0 {
			// a loopback interface has no global unicast address
			if a, err := InterfaceAddr(ifc.Name); err == nil {
				t.Errorf("InterfaceAddr(%s) = %v; want an error", ifc.Name, a)
			}
		}
	}
}

func TestLocalAddr(t *testing.T) {
	t.Cleanup(func() { SetLocalAddr(netip.Addr{}) })

	engine := netip.MustParseAddr("192.0.2.1")
	session := netip.MustParseAddr("192.0.2.2")

	if a := LocalAddr(context.Background()); a.IsValid() {
		t.Errorf("LocalAddr = %v before any setting; want the zero Addr", a)
	}

	SetLocalAddr(engine)
	if a := LocalAddr(context.Background()); a != engine {
		t.Errorf("LocalAddr = %v; want the engine's %v", a, engine)
	}
	if a := LocalAddr(WithLocalAddr(context.Background(), session)); a != session {
		t.Errorf("LocalAddr = %v; want the context's %v", a, session)
	}
	if a := LocalAddr(WithLocalAddr(context.Background(), netip.Addr{})); a != engine {
		t.Errorf("LocalAddr = %v for a context naming the zero Addr; want the engine's %v", a, engine)
	}
}

func TestNewDialContextLocalAddr(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		if c, err := l.Accept(); err == nil {
			_ = c.Close()
		}
	}()

	ctx := WithLocalAddr(context.Background(), netip.MustParseAddr("127.0.0.1"))
	c, err := NewDialContext(time.Second)(ctx, "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial from 127.0.0.1: %v", err)
	}
	defer func() { _ = c.Close() }()

	if a, ok := c.LocalAddr().(*net.TCPAddr); !ok || !a.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Errorf("the connection left from %v; want 127.0.0.1", c.LocalAddr())
	}

	ctx = WithLocalAddr(context.Background(), netip.MustParseAddr("192.0.2.1"))
	if c, err := NewDialContext(time.Second)(ctx, "tcp", l.Addr().String()); err == nil {
		_ = c.Close()
		t.Error("a dial from an address on no interface succeeded")
	}
}
