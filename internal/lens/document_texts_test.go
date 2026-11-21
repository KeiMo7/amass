// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// DocumentTexts gives the document model the passages of each stored File
// the subject publishes, with how many statements are already stored, and
// leaves out Files without passages.
func TestDocumentTexts(t *testing.T) {
	g := graphtest.VendorFixture()
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

	for _, d := range []struct{ url, file string }{
		{"https://www.colgate.edu/it/plan.pdf", "f-plan"},
		{"https://www.colgate.edu/logo.png", "f-logo"},
	} {
		asset("u-"+d.file, "URL", d.url, map[string]any{"url": d.url})
		link("u-"+d.file, "domain", "www.colgate.edu")
		asset(d.file, "File", d.url, map[string]any{"url": d.url})
		link("u-"+d.file, "file", d.file)
	}
	g.EvidenceByID["f-plan"] = []graph.Evidence{
		graphtest.SimpleProp(propDocTitle, "IT Strategic Plan"),
		graphtest.SimpleProp(propDocPassage, "The Colgate Foundation is a division of Colgate University."),
		graphtest.SimpleProp(propDocPassage, "Colgate University uses Microsoft 365 for email."),
		graphtest.SimpleProp(propDocStatement, `{"subject":"The Colgate Foundation","predicate":"unit_of"}`),
	}
	g.EvidenceByID["f-logo"] = []graph.Evidence{graphtest.SimpleProp(propDocTitle, "Logo")}

	docs, err := DocumentTexts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 {
		t.Fatalf("documents %+v, want only the one with passages", docs)
	}
	d := docs[0]
	if d.FileID != "f-plan" || d.URL != "https://www.colgate.edu/it/plan.pdf" || len(d.Passages) != 2 ||
		d.Statements != 1 {
		t.Fatalf("document %+v", d)
	}
	if d.Passages[0] != "The Colgate Foundation is a division of Colgate University." {
		t.Fatalf("passages out of order: %v", d.Passages)
	}
}
