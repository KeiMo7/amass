// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// companionStore is a runStore that also answers edge queries and deletes.
type companionStore struct{ runStore }

func (s *companionStore) IncomingEdges(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.Edge, error) {
	return nil, nil
}

func (s *companionStore) OutgoingEdges(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.Edge, error) {
	return nil, nil
}

func (s *companionStore) DeleteEntity(context.Context, string) error { return nil }

func (s *companionStore) FindEntityTags(context.Context, *dbt.Entity, time.Time, ...string) ([]*dbt.EntityTag, error) {
	return nil, nil
}

func (s *companionStore) CreateEdgeProperty(context.Context, *dbt.Edge, oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{ID: "et"}, nil
}

func (s *companionStore) DeleteEdgeTag(context.Context, string) error { return nil }

// companionActivity records what a companion submits and counts.
type companionActivity struct {
	mu        sync.Mutex
	submitted []string
	counts    map[string]int
}

func (a *companionActivity) activity() collect.Activity {
	return collect.Activity{
		Submit: func(_ context.Context, asset oam.Asset) (string, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.submitted = append(a.submitted, string(asset.AssetType())+":"+asset.Key())
			return "lead-" + asset.Key(), nil
		},
		Count: func(name string, n int) {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.counts[name] += n
		},
	}
}

// During a run the companion fetches the target's documents, reads all of
// their text, stores the findings and hands the run's session every asset
// they name that the engine collects from and the database lacks, within the
// run's lead budget; an asset the database holds is never a lead.
func TestDocumentCompanionSubmitsLeads(t *testing.T) {
	g := documentFixture()
	reply := `{"category": "annual_report", "assets": [
	  {"type": "FQDN", "value": "vpn.herkimer.edu", "quote": "Staff connect remotely through vpn.herkimer.edu"},
	  {"type": "Netblock", "value": "192.0.2.0/24", "quote": "the data center hosts 192.0.2.0/24"},
	  {"type": "Product", "value": "Workday", "quote": "The college uses Workday for payroll."}],
	 "statements": [
	  {"subject": "Herkimer College Foundation", "subject_type": "Organization", "predicate": "unit_of",
	   "object": "Herkimer County Community College", "object_type": "Organization",
	   "quote": "The Herkimer College Foundation is a division of Herkimer County Community College."}],
	 "attributes": []}`
	store := &companionStore{runStore{props: map[string]oam.Property{}}}
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	fetcher := &textFetcher{texts: map[string]string{"https://www.colgate.edu/a.pdf": docText}}
	c := &DocumentCompanion{Graph: g, Store: store, Journal: j, Model: &docModel{replies: []string{reply}},
		ModelID: "test-model", Interval: time.Hour, MaxLeads: 3, Fetcher: fetcher,
		Schema: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}}
	run := collect.Run{ID: "run1", Plan: collect.Plan{ScopeType: "domain", ScopeValue: "colgate.edu"}}
	act := &companionActivity{counts: map[string]int{}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := c.Begin(ctx, run, act.activity())
	if pending == nil {
		t.Fatal("no pending report")
	}
	// the engine is done: the companion reads what remains before the run ends
	if !pending() {
		t.Fatal("not pending before a pass after the engine finished")
	}
	deadline := time.Now().Add(5 * time.Second)
	for pending() {
		if time.Now().After(deadline) {
			t.Fatal("the companion never finished its pass")
		}
		time.Sleep(5 * time.Millisecond)
	}

	act.mu.Lock()
	defer act.mu.Unlock()
	got := append([]string(nil), act.submitted...)
	sort.Strings(got)
	// a host, a range and an organization fit the budget of 3; the second
	// organization waits for the budget, and the product is no lead
	want := []string{"FQDN:vpn.herkimer.edu", "Netblock:192.0.2.0/24", "Organization:Herkimer College Foundation"}
	if len(got) != len(want) {
		t.Fatalf("submitted %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("submitted %v, want %v", got, want)
		}
	}
	if act.counts[ActivityDocumentsRead] != 1 || act.counts[ActivityLeads] != 3 ||
		act.counts[ActivityLeadsWaiting] != 1 {
		t.Fatalf("counts %v", act.counts)
	}

	leads, err := j.DocumentLeads()
	if err != nil || len(leads) != 3 {
		t.Fatalf("journaled leads %+v, %v", leads, err)
	}
	for _, l := range leads {
		if !review.IsDocumentLead(l.ID) || l.RunID != "run1" || l.Type == "" {
			t.Errorf("lead %+v", l)
		}
	}

	// the engine confirmed none of them when the run ended: all expire
	c.Finish(context.Background(), run)
	leads, _ = j.DocumentLeads()
	for _, l := range leads {
		if l.Status != review.ProposalRetracted || l.Reviewer != review.DocumentLeadExpiredReviewer {
			t.Errorf("unconfirmed lead not expired: %+v", l)
		}
	}
}

// Every collectable type a document can name has a lead; people and products
// do not, and a malformed value gives none.
func TestLeadFor(t *testing.T) {
	for _, tc := range []struct {
		typ, value, key string
	}{
		{"FQDN", "VPN.Example.edu.", "vpn.example.edu"},
		{"IPAddress", "192.0.2.10", "192.0.2.10"},
		{"Netblock", "192.0.2.7/24", "192.0.2.0/24"},
		{"AutonomousSystem", "AS64496", "64496"},
		{"Identifier", "Jane.Doe@Example.edu", "email:jane.doe@example.edu"},
		{"URL", "https://portal.example.edu/login", "https://portal.example.edu/login"},
		{"Phone", "+1 315-866-0300", "+13158660300"},
		{"StreetAddress", "100 Reservoir Rd, Herkimer, NY 13350", "100 Reservoir Rd, Herkimer, NY 13350"},
		{"Organization", "Herkimer College Foundation", "Herkimer College Foundation"},
	} {
		l, ok := leadFor(tc.typ, tc.value)
		if !ok || l.asset.Key() != tc.key || string(l.asset.AssetType()) != tc.typ {
			t.Errorf("leadFor(%s, %q) = %v %v, want key %q", tc.typ, tc.value, l.asset, ok, tc.key)
		}
	}
	for _, tc := range []struct{ typ, value string }{
		{"Person", "Jane Doe"}, {"Product", "Workday"}, {"FQDN", "not a host"}, {"Phone", "555-0100"},
		{"Identifier", "LEI 5493001KJTIIGC8Y1R12"}, {"Organization", "third parties"},
		{"Organization", "Office of Events"}, {"Organization", "Department of Computer Science"},
	} {
		if _, ok := leadFor(tc.typ, tc.value); ok {
			t.Errorf("leadFor(%s, %q) gave a lead", tc.typ, tc.value)
		}
	}
}

// A negative lead budget stores findings but submits nothing.
func TestDocumentCompanionWithoutLeads(t *testing.T) {
	st := &companionRun{seen: map[string]bool{}}
	act := &companionActivity{counts: map[string]int{}}
	c := &DocumentCompanion{MaxLeads: -1}
	c.submitLeads(context.Background(), collect.Run{ID: "r"}, act.activity(), st, DocumentResult{
		Stored: []review.StoredStatement{{Kind: FindingAsset, Subject: "vpn.example.edu", SubjectType: "FQDN"}}})
	if len(act.submitted) != 0 {
		t.Fatalf("submitted %v with leads off", act.submitted)
	}
}

// A generic unit of the publisher is not a lead; a public body with a unit-like
// name, or a longer name, is.
func TestGenericUnit(t *testing.T) {
	for name, want := range map[string]bool{
		"Office of Events":                       true,
		"Department of Computer Science":         true,
		"Center for Teaching":                    true,
		"U.S. Department of Education":           false,
		"New York State Office of Mental Health": false,
		"Sodexho":                                false,
		"Office of the Vice President for Academic Affairs and Provost": false,
	} {
		if got := genericUnit(name); got != want {
			t.Errorf("genericUnit(%q) = %v, want %v", name, got, want)
		}
	}
}
