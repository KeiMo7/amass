// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"slices"
	"testing"
)

func TestStatementCuesLoad(t *testing.T) {
	c := StatementCueRules()
	if c.MaxPassages <= 0 || len(c.Cues) == 0 {
		t.Fatalf("cues %+v", c)
	}
}

// A phrase matches without case, across line breaks, on word boundaries only.
func TestStatementCuesMatch(t *testing.T) {
	c := StatementCueRules()
	if got := c.Match("The Foundation is a Division\nof the College."); !slices.Equal(got, []string{"org_structure"}) {
		t.Errorf("division: %v", got)
	}
	if got := c.Match("Jane Doe, Chief Information Officer, and the IT staff"); !slices.Equal(got, []string{"role"}) {
		t.Errorf("role: %v", got)
	}
	if got := c.Match("The portal is powered by Ellucian."); !slices.Equal(got, []string{"product_use", "supplier"}) {
		t.Errorf("powered by: %v", got)
	}
	if got := c.Match("Our vendors list and the vendorization of things"); len(got) != 0 {
		t.Errorf("a word containing a cue matched: %v", got)
	}
}
