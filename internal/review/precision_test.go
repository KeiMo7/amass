// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"strings"
	"testing"
)

func precisionEntry(status string, signals ...string) OwnershipEntry {
	return OwnershipEntry{Status: status, Proposal: OwnershipProposal{SignalIDs: signals}}
}

// Each signal is judged by the proposals it stood behind; retractions and
// pending proposals do not count against it, and a signal with few reviewed
// proposals is flagged and listed after the measured ones.
func TestSignalPrecisions(t *testing.T) {
	var entries []OwnershipEntry
	for range 4 {
		entries = append(entries, precisionEntry(ProposalApplied, "shared_registrant_details", "hosting_in_footprint"))
	}
	entries = append(entries,
		precisionEntry(ProposalRejected, "hosting_in_footprint"),
		precisionEntry(ProposalRejected, "hosting_in_footprint"),
		precisionEntry(ProposalApplied, "shared_registrant_details"),
		precisionEntry(ProposalRetracted, "shared_registrant_details"),
		precisionEntry(ProposalPending, "caa_account_binding"),
		precisionEntry(ProposalApplied),
	)

	rows := SignalPrecisions(entries)
	if len(rows) != 3 {
		t.Fatalf("rows = %+v; want three signals", rows)
	}

	want := []SignalPrecision{
		{Signal: "hosting_in_footprint", Applied: 4, Rejected: 2, Precision: 4.0 / 6},
		{Signal: "shared_registrant_details", Applied: 5, Retracted: 1, Precision: 1},
		{Signal: "caa_account_binding", Pending: 1, Thin: true},
	}
	for i, w := range want {
		if rows[i] != w {
			t.Errorf("row %d = %+v; want %+v", i, rows[i], w)
		}
	}

	text := FormatSignalPrecisions(rows)
	for _, s := range []string{"hosting_in_footprint", "0.67", "-*"} {
		if !strings.Contains(text, s) {
			t.Errorf("report lacks %q:\n%s", s, text)
		}
	}
	if got := FormatSignalPrecisions(nil); !strings.Contains(got, "No ownership proposals") {
		t.Errorf("empty report = %q", got)
	}
}
