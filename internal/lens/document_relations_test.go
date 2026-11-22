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

// docGraph resolves organizations, people and addresses by exact name, as the
// repositories do: a name two organizations share is ambiguous.
type docGraph struct {
	graphtest.VendorGraph
	orgs map[string][]string
}

func (g docGraph) ResolveOrganizations(_ context.Context, q graph.OrganizationQuery, _ int) (graph.OrganizationResolution,
	error) {
	res := graph.OrganizationResolution{Query: q, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	name := q.Name
	if name == "" {
		name = q.LegalName
	}
	for _, id := range g.orgs[strings.ToLower(name)] {
		res.Candidates = append(res.Candidates, graph.OrganizationCandidate{Asset: g.Assets[id]})
	}
	switch len(res.Candidates) {
	case 0:
	case 1:
		res.Status = "matched"
	default:
		res.Status = "ambiguous"
	}
	return res, nil
}

func (g docGraph) ResolveAsset(_ context.Context, s graph.AssetSelector, _ int) (graph.AssetResolution, error) {
	res := graph.AssetResolution{Query: s, Status: "not_found", Candidates: []graph.OrganizationCandidate{}}
	for _, a := range g.Assets {
		if a.Type == s.Type && a.Key == s.Value {
			res.Candidates = append(res.Candidates, graph.OrganizationCandidate{Asset: a})
		}
	}
	if len(res.Candidates) == 1 {
		res.Status = "matched"
	}
	return res, nil
}

// documentRelationFixture publishes two documents on colgate.edu stating its
// structure, funding and address, alongside findings that must give nothing:
// an ambiguous name, an unknown one, a link already stored, a predicate with
// no OAM relation and a finding that is not a relationship.
func documentRelationFixture() docGraph {
	g := docGraph{VendorGraph: graphtest.VendorFixture(), orgs: map[string][]string{}}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	asset := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	org := func(id, name string) {
		asset(id, "Organization", name, map[string]any{"name": name})
		g.orgs[strings.ToLower(name)] = append(g.orgs[strings.ToLower(name)], id)
	}

	g.orgs["colgate university"] = []string{"colgate"}
	org("foundation", "Colgate Foundation")
	org("funder", "Example Funder")
	org("acme-1", "Acme Holdings")
	org("acme-2", "Acme Holdings")
	org("bookstore", "Colgate Bookstore")
	link("colgate", "subsidiary", "bookstore")
	asset("addr", "StreetAddress", "13 Oak Drive, Hamilton, NY 13346", map[string]any{"address": "13 Oak Drive, Hamilton, NY 13346"})

	rel := func(subj, subjType, pred, obj, objType, sha string) graph.Evidence {
		return graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"`+subj+`","subject_type":"`+
			subjType+`","predicate":"`+pred+`","object":"`+obj+`","object_type":"`+objType+`","sha256":"`+sha+`"}`)
	}
	for _, d := range []struct{ url, file, sha string }{
		{"https://www.colgate.edu/report.pdf", "f-report", "v1"},
		{"https://www.colgate.edu/catalog.pdf", "f-catalog", "v2"},
	} {
		asset("u-"+d.file, "URL", d.url, map[string]any{"url": d.url})
		link("u-"+d.file, "domain", "www.colgate.edu")
		asset(d.file, "File", d.url, map[string]any{"url": d.url, "type": "application/pdf"})
		link("u-"+d.file, "file", d.file)
		g.EvidenceByID[d.file] = []graph.Evidence{
			rel("Colgate  Foundation", "Organization", "unit_of", "Colgate University", "Organization", d.sha),
		}
	}
	g.EvidenceByID["f-report"] = append(g.EvidenceByID["f-report"],
		rel("Colgate University", "Organization", "funded_by", "Example Funder", "Organization", "v1"),
		rel("Colgate University", "Organization", "located_at", "13 Oak Drive, Hamilton, NY 13346", "StreetAddress", "v1"),
		rel("Acme Holdings", "Organization", "subsidiary_of", "Colgate University", "Organization", "v1"),
		rel("Nowhere Institute", "Organization", "unit_of", "Colgate University", "Organization", "v1"),
		rel("Colgate Bookstore", "Organization", "unit_of", "Colgate University", "Organization", "v1"),
		rel("Colgate University", "Organization", "partner_of", "Example Funder", "Organization", "v1"),
		graphtest.SimpleProp(propDocStatement, `{"kind":"asset","subject":"vpn.colgate.edu","subject_type":"FQDN"}`),
	)
	return g
}

// The documents colgate.edu publishes give a review proposal for each
// relationship they state between stored assets, weighted as first-party and,
// when two document versions agree, corroborated; nothing else gives one.
func TestFindDocumentRelations(t *testing.T) {
	g := documentRelationFixture()
	r, err := FindDocumentRelations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != DocumentRelationKind {
		t.Fatalf("kind %q", r.Kind)
	}

	got := map[string]RelationCandidate{}
	for _, c := range r.Candidates {
		got[c.FromID+" "+c.Label+" "+c.ToID] = c
	}
	// three between stored assets, and the unstored unit of the publisher
	if len(got) != 4 {
		t.Fatalf("candidates %+v", r.Candidates)
	}
	if c := got["colgate org_unit "]; c.NewTo == nil || c.NewTo.Name != "Nowhere Institute" ||
		c.NewTo.Key != "Colgate University / Nowhere Institute" {
		t.Errorf("new unit candidate %+v", c)
	}

	unit, ok := got["colgate org_unit foundation"]
	if !ok || unit.Confidence != 50 || len(unit.EvidenceIDs) != 2 || len(unit.Signals) != 2 {
		t.Fatalf("unit candidate %+v: want the parent first, corroborated by both documents", unit)
	}
	if !strings.Contains(unit.Signals[0], "unit of another") || !strings.Contains(strings.Join(unit.Signals, " "),
		"https://www.colgate.edu/catalog.pdf") {
		t.Errorf("unit signals %v", unit.Signals)
	}
	if c, ok := got["colgate funding_source funder"]; !ok || c.Confidence != 40 || len(c.EvidenceIDs) != 1 {
		t.Errorf("funder candidate %+v: want one first-party document", c)
	}
	if _, ok := got["colgate street_address addr"]; !ok {
		t.Error("the stored address was not proposed")
	}
	if r.Candidates[0].FromID != "colgate" || r.Candidates[0].ToID != "foundation" {
		t.Errorf("the corroborated candidate is not first: %+v", r.Candidates[0])
	}
}

// A graph without exact lookups cannot attach document evidence safely.
func TestFindDocumentRelationsNeedsExactLookups(t *testing.T) {
	g := graphtest.VendorFixture()
	if _, err := FindDocumentRelations(context.Background(), g.FakeGraph, graphtest.VendorCatalog{
		PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"], LensLimits{}); err == nil {
		t.Error("ran without exact lookups")
	}
}

// Every document signal stays supporting: the bonuses never lift one past the
// cap, and the cap is below every strong signal.
func TestDocumentSignalCatalog(t *testing.T) {
	if len(DocumentSignals()) == 0 {
		t.Fatal("no document signals")
	}
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	for _, tc := range []struct {
		firstParty bool
		versions   int
		want       float64
	}{
		{false, 1, 0.15}, {true, 1, 0.20}, {false, 3, 0.20}, {true, 2, 0.25},
	} {
		if got := DocumentWeight(tc.firstParty, tc.versions); !near(got, tc.want) {
			t.Errorf("DocumentWeight(%v, %d) = %.2f, want %.2f", tc.firstParty, tc.versions, got, tc.want)
		}
	}
	if w := DocumentSignalWeights(); w.Cap >= 0.35 {
		t.Errorf("cap %.2f reaches a strong signal", w.Cap)
	}
	if documentConfidence(DocumentWeight(true, 2)) != 50 || documentConfidence(DocumentWeight(true, 1)) != 40 {
		t.Error("confidence is not twice the weight")
	}

	bad := documentSignalCatalog{Weights: DocumentWeights{Base: 0.15, Cap: 0.4}}
	if validateDocumentSignals(bad) == nil {
		t.Error("a cap that reaches a strong signal was accepted")
	}
	bad = documentSignalCatalog{Weights: DocumentWeights{Base: 0.15, Cap: 0.25}, Signals: []DocumentSignal{{
		ID: "x", Title: "x", Rationale: "x", Guards: []string{"x"}, Predicates: []string{"unit_of"},
		SubjectType: "Organization", ObjectType: "Organization", Label: "subsidiary", Direction: "inverse"}}}
	if validateDocumentSignals(bad) == nil {
		t.Error("a label that contradicts the predicate catalog was accepted")
	}
}

// A unit the publisher's documents name with the publisher placeholder is
// proposed under the publisher: as a new unit when it is not stored, or is
// stored only as another organization's unit; never as a link to that other
// organization's office of the same name.
func TestFindDocumentRelationsPublisherUnits(t *testing.T) {
	g := documentRelationFixture()
	g.Assets["hamilton-counseling"] = graph.Asset{ID: "hamilton-counseling", Type: "Organization",
		Key: "Hamilton College / Counseling Center", Content: map[string]any{"name": "Counseling Center"}}
	g.orgs["counseling center"] = []string{"hamilton-counseling"}
	g.Links = append(g.Links, graph.Relation{ID: "hc", FromID: "hamilton", ToID: "hamilton-counseling",
		Label: "org_unit", Type: "SimpleRelation"})
	g.EvidenceByID["f-catalog"] = append(g.EvidenceByID["f-catalog"],
		graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"Counseling Center",`+
			`"subject_type":"Organization","predicate":"unit_of","object":"`+DocumentPublisher+`",`+
			`"object_type":"Organization","sha256":"v2"}`))

	r, err := FindDocumentRelations(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	var unit *RelationCandidate
	for i, c := range r.Candidates {
		if c.ToID == "hamilton-counseling" {
			t.Fatalf("linked colgate to another college's office: %+v", c)
		}
		if c.NewTo != nil && c.NewTo.Name == "Counseling Center" {
			unit = &r.Candidates[i]
		}
	}
	if unit == nil || unit.FromID != "colgate" || unit.Label != "org_unit" ||
		unit.NewTo.Key != "Colgate University / Counseling Center" {
		t.Fatalf("publisher unit %+v in %+v", unit, r.Candidates)
	}
	if !strings.Contains(strings.Join(unit.Signals, " "), "its publisher") {
		t.Errorf("signals %v do not say the unit is the publisher's", unit.Signals)
	}
}

func TestUnitKey(t *testing.T) {
	parent := graph.Asset{ID: "7", Key: "Colgate University"}
	if got := UnitKey(parent, "  Counseling   Center "); got != "Colgate University / Counseling Center" {
		t.Errorf("UnitKey = %q", got)
	}
}
