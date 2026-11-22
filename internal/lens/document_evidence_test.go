// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// valueDocGraph finds Files by the text of their doc_statement properties,
// as the repositories' value search does.
type valueDocGraph struct{ graphtest.VendorGraph }

func (g valueDocGraph) FindByTagValue(_ context.Context, assetType, name, value string, _ bool, limit int) ([]graph.Asset,
	bool, error) {
	var out []graph.Asset
	for id, a := range g.Assets {
		if a.Type != assetType {
			continue
		}
		for _, v := range propertyValues(g.EvidenceByID[id], name) {
			if strings.Contains(v, value) {
				out = append(out, a)
				break
			}
		}
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func (g valueDocGraph) FindByAttribute(context.Context, string, string, string, bool, int) ([]graph.Asset, bool, error) {
	return nil, false, ErrValueSearchUnsupported
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

// A document stating the subject operates a stored host gives it a weighted
// document signal; it raises nothing to propose on its own, and the decision
// automatic attribution acts on ignores it.
func TestDocumentOperatorSignal(t *testing.T) {
	g := valueDocGraph{graphtest.VendorFixture()}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	g.Assets["portal"] = graph.Asset{ID: "portal", Type: "FQDN", Key: "portal.colgate-partners.example",
		Content: map[string]any{"name": "portal.colgate-partners.example"}}
	g.Assets["f-report"] = graph.Asset{ID: "f-report", Type: "File", Key: "https://www.colgate.edu/report.pdf",
		Content: map[string]any{"url": "https://www.colgate.edu/report.pdf"}}
	g.EvidenceByID["f-report"] = []graph.Evidence{graphtest.SimpleProp(propDocStatement,
		`{"kind":"relation","subject":"portal.colgate-partners.example","subject_type":"FQDN",`+
			`"predicate":"operated_by","object":"Colgate  University","object_type":"Organization","sha256":"v1"}`)}

	r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}
	var found *GapCandidate
	for i := range r.Candidates {
		if r.Candidates[i].AssetID == "portal" {
			found = &r.Candidates[i]
		}
	}
	if found == nil {
		t.Fatalf("no candidate for the host the document names: %+v", r.Candidates)
	}
	var sig *GapSignal
	for i := range found.Signals {
		if found.Signals[i].Signal == sigDocumentOperator {
			sig = &found.Signals[i]
		}
	}
	if sig == nil || sig.Kind != DocumentSignalKind || !strings.Contains(sig.Via, "report.pdf") {
		t.Fatalf("signals %+v", found.Signals)
	}
	if !near(sig.Weight, 0.15) && !near(sig.Weight, 0.20) {
		t.Errorf("weight %.2f, want 0.15, or 0.20 when first-party", sig.Weight)
	}
	if found.Decision == GapPropose || found.AutoDecision == GapPropose {
		t.Errorf("a document alone proposed ownership: %+v", found)
	}
}

// A document signal adds its own weight, never more than the catalog's, and
// what may be written automatically is decided without it.
func TestDocumentSignalsNeverDecideAutomaticWrites(t *testing.T) {
	strong := GapSignal{Signal: "shared_registrant_details", Kind: SignalIdentity}
	doc := GapSignal{Signal: sigDocumentOperator, Kind: DocumentSignalKind, Weight: 0.15}

	score, decision := ScoreGap([]GapSignal{strong, doc}, true)
	if decision != GapPropose {
		t.Fatalf("decision with the document signal %q, want it to corroborate for review", decision)
	}
	def, _ := LookupOwnershipSignal("shared_registrant_details")
	if !near(score, def.Weight+0.15) {
		t.Errorf("score %.2f, want the strong weight plus the document's own 0.15", score)
	}
	if _, auto := ScoreGap(WithoutDocumentSignals([]GapSignal{strong, doc}), true); auto == GapPropose {
		t.Error("the document signal still decided the automatic write")
	}

	// a registration number alone is review; a document must not tip it
	// into an automatic merge
	reg := GapSignal{Signal: "shared_registration", Kind: "identity"}
	former := GapSignal{Signal: "document_former_name", Kind: DocumentSignalKind, Weight: 0.15}
	if AutoMergeable([]GapSignal{reg, former}) {
		t.Error("a document helped a merge be applied automatically")
	}
	brand := GapSignal{Signal: "same_brand_name", Kind: "name"}
	if !AutoMergeable([]GapSignal{reg, brand, former}) {
		t.Error("a merge that qualifies without the document was refused")
	}
}

// Documents that give a former name support a merge of the two records;
// documents that call one the parent or unit of the other count against it.
func TestDocumentLinksInDuplicateSignals(t *testing.T) {
	links := buildDocLinks([]docFinding{
		{st: docStatement{Kind: "relation", Subject: "SUNY  Polytechnic Institute", SubjectType: "Organization",
			Predicate: "formerly_known_as", Object: "SUNY Institute of Technology", ObjectType: "Organization",
			SHA256: "v1"}, fileID: "f1", url: "https://sunypoly.edu/history.pdf"},
		{st: docStatement{Kind: "relation", Subject: "SUNY Polytechnic Institute", SubjectType: "Organization",
			Predicate: "formerly_known_as", Object: "suny institute of technology", ObjectType: "Organization",
			SHA256: "v2"}, fileID: "f2", url: "https://sunypoly.edu/report.pdf"},
		{st: docStatement{Kind: "relation", Subject: "Colgate Foundation", SubjectType: "Organization",
			Predicate: "unit_of", Object: "Colgate University", ObjectType: "Organization", SHA256: "v1"},
			fileID: "f3", url: "https://colgate.edu/a.pdf"},
	})
	profile := func(id, name string) *orgProfile {
		p := &orgProfile{asset: graph.Asset{ID: id, Type: "Organization"}, brands: map[string]bool{},
			ids: map[string]map[string]bool{}, contacts: map[string]bool{}, locations: map[string]bool{},
			addresses: map[string]bool{}, related: map[string]bool{}}
		p.addName(name)
		for other, l := range links[docFold(name)] {
			if p.docs == nil {
				p.docs = map[string]*docLink{}
			}
			p.docs[other] = l
		}
		return p
	}

	poly, sunyit := profile("a", "suny polytechnic institute"), profile("b", "SUNY Institute of Technology")
	var former *GapSignal
	for _, s := range pairSignals(poly, sunyit) {
		if s.Signal == "document_former_name" {
			s := s
			former = &s
		}
	}
	if former == nil || former.Kind != DocumentSignalKind || !near(former.Weight, 0.20) {
		t.Fatalf("former-name signal %+v: want one, corroborated by two versions", former)
	}

	found := false
	for _, s := range pairSignals(profile("c", "Colgate Foundation"), profile("d", "Colgate University")) {
		if s.Signal == "document_former_name" {
			t.Error("a unit was counted toward a merge")
		}
		if def, _ := DuplicateSignal(s.Signal); def.Strength == StrengthNegative && strings.Contains(s.Via, "unit_of") {
			found = true
		}
	}
	if !found {
		t.Error("a document calling one the unit of the other did not count against the merge")
	}
}
