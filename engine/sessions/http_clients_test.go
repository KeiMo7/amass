// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"testing"
	"time"
)

// The Bulk client waits minutes for a slow index to start answering, where the
// General client gives up after seconds; both are paced.
func TestBulkClientWaitsForSlowIndexes(t *testing.T) {
	c, err := NewClients(4)
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
