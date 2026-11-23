// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	amassnet "github.com/owasp-amass/amass/v5/internal/net"
)

// The Bulk client waits minutes for a slow index to start answering, where the
// General client gives up after seconds; both are paced.
func TestBulkClientWaitsForSlowIndexes(t *testing.T) {
	c, err := NewClients(4, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()

	if c.Bulk == nil || c.Bulk.Timeout < bulkTimeout || c.bulkTr.ResponseHeaderTimeout < 2*time.Minute {
		t.Fatalf("bulk client %+v, header timeout %v", c.Bulk, c.bulkTr.ResponseHeaderTimeout)
	}
	if c.genTr.ResponseHeaderTimeout >= c.bulkTr.ResponseHeaderTimeout {
		t.Error("the General client should not wait as long as the Bulk client")
	}
	if c.Bulk.Transport == c.bulkTr {
		t.Error("the Bulk client is not paced")
	}
}

// A session's clients send from its local address whatever context a request
// carries, since a plugin's request context need not come from the session.
func TestBoundDialUsesTheSessionAddress(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// 192.0.2.0/24 is reserved for documentation, so no interface has it
	other := amassnet.WithLocalAddr(context.Background(), netip.MustParseAddr("192.0.2.1"))

	c, err := boundDial(time.Second, netip.MustParseAddr("127.0.0.1"))(other, "tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("the bound dial did not use the session address: %v", err)
	}
	_ = c.Close()

	if c, err := boundDial(time.Second, netip.Addr{})(other, "tcp", l.Addr().String()); err == nil {
		_ = c.Close()
		t.Error("without a session address, the context's address was not used")
	}
}
