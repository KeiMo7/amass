// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOrgNameKey(t *testing.T) {
	for name, want := range map[string]string{
		"Google Trust Services LLC":        "google trust services",
		"Acme, Inc.":                       "acme",
		"at&t enterprises, llc":            "at&t enterprises",
		"Société Générale S.A.":            "societe generale",
		"Proofpoint Pty Ltd":               "proofpoint",
		"Johnson & Johnson":                "johnson and johnson",
		"The Trustees of Hamilton College": "hamilton college",
		"Acme Intl Mfg Co":                 "acme international manufacturing",
		"  Acme   (Holdings)  ":            "acme holdings",
		"GlobalSign nv-sa":                 "globalsign",
		"Amazon.com, Inc.":                 "amazon.com",
		"Canva Pty Ltd":                    "canva",
		"DigiCert Inc":                     "digicert",
		"procter & gamble co.":             "procter and gamble",
		"national grid plc":                "national grid",
		"hopkins & sons plumbing":          "hopkins and sons plumbing",
		"Trustees of Dartmouth College":    "dartmouth college",
		"The North Face Inc":               "the north face",
		"S.A.":                             "s.a",
		"Inc.":                             "inc",
		"The Trustees of":                  "the trustees of",
		"":                                 "",
		" ,. ":                             "",
	} {
		if got := OrgNameKey(name); got != want {
			t.Errorf("OrgNameKey(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsOrgLegalForm(t *testing.T) {
	for w, want := range map[string]bool{"Inc.": true, "LLC": true, "pty ltd": true, "S.A.": true, "Acme": false,
		"university": false} {
		if got := IsOrgLegalForm(w); got != want {
			t.Errorf("IsOrgLegalForm(%q) = %v, want %v", w, got, want)
		}
	}
	if !IsOrgGenericWord("services") || IsOrgGenericWord("hartwick") || len(OrgGenericWords()) == 0 {
		t.Error("the generic words were not loaded")
	}
}

// TestOrgNamePairs checks OrgNameMatch against the labeled pairs, both ways.
func TestOrgNamePairs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "org_name_pairs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		About string `json:"_about"`
		Pairs []struct {
			A, B, Want string
		} `json:"pairs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Pairs) < 20 {
		t.Fatalf("only %d labeled pairs", len(doc.Pairs))
	}

	for _, p := range doc.Pairs {
		for _, order := range [][2]string{{p.A, p.B}, {p.B, p.A}} {
			exact, near := OrgNameMatch(order[0], order[1])
			got := "none"
			switch {
			case exact:
				got = "exact"
			case near:
				got = "near"
			}
			if got != p.Want {
				t.Errorf("OrgNameMatch(%q, %q) = %s, want %s (keys %q, %q)", order[0], order[1], got, p.Want,
					OrgNameKey(order[0]), OrgNameKey(order[1]))
			}
		}
	}
}
