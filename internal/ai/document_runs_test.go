// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/review"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
)

// runStore keeps the properties written to any File.
type runStore struct {
	props map[string]oam.Property
	next  int
}

func (s *runStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	return &dbt.Entity{ID: id, Asset: &oamfile.File{URL: id}}, nil
}

func (s *runStore) CreateEntityProperty(_ context.Context, _ *dbt.Entity, p oam.Property) (*dbt.EntityTag, error) {
	s.next++
	id := fmt.Sprintf("t%d", s.next)
	s.props[id] = p
	return &dbt.EntityTag{ID: id, Property: p}, nil
}

func (s *runStore) DeleteEntityTag(_ context.Context, id string) error {
	if _, ok := s.props[id]; !ok {
		return errors.New("not found")
	}
	delete(s.props, id)
	return nil
}

// A run reads the documents with passages and no statements, up to its limit,
// stores what passes validation, and counts the rest as skipped or remaining.
func TestReadDocuments(t *testing.T) {
	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	for _, f := range []string{"a", "b", "c"} {
		url := "https://www.colgate.edu/" + f + ".pdf"
		g.Assets["u-"+f] = graph.Asset{ID: "u-" + f, Type: "URL", Key: url, Content: map[string]any{"url": url}}
		g.Assets["f-"+f] = graph.Asset{ID: "f-" + f, Type: "File", Key: url, Content: map[string]any{"url": url}}
		g.Links = append(g.Links,
			graph.Relation{ID: "u-" + f + "-domain", FromID: "u-" + f, ToID: "www.colgate.edu", Label: "domain",
				Type: "SimpleRelation"},
			graph.Relation{ID: "u-" + f + "-file", FromID: "u-" + f, ToID: "f-" + f, Label: "file",
				Type: "SimpleRelation"})
		ev := []graph.Evidence{graphtest.SimpleProp("doc_passage", docPassages[0]),
			graphtest.SimpleProp("doc_passage", docPassages[1])}
		if f == "b" {
			ev = append(ev, graphtest.SimpleProp(review.PropDocStatement, `{"predicate":"unit_of"}`))
		}
		g.EvidenceByID["f-"+f] = ev
	}

	reply := `{"category": "staff_directory", "statements": [
	 {"subject": "Herkimer College Foundation", "subject_type": "Organization", "predicate": "unit_of",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "The Herkimer College Foundation is a division of Herkimer County Community College."},
	 {"subject": "Acme", "subject_type": "Organization", "predicate": "supplied_by",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "Acme supplies the College"}]}`
	store := &runStore{props: map[string]oam.Property{}}
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	opts := DocumentRunOptions{Model: &docModel{replies: []string{reply}}, ModelID: "test-model", Max: 1,
		Schema: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}}

	// a dry run stores nothing
	dry := opts
	dry.DryRun = true
	run, err := ReadDocuments(context.Background(), g, store, j, g.Assets["colgate.edu"], dry)
	if err != nil {
		t.Fatal(err)
	}
	if run.Read != 1 || len(store.props) != 0 || len(run.Documents) != 1 || len(run.Documents[0].Stored) != 2 {
		t.Fatalf("dry run %+v, stored %d", run, len(store.props))
	}

	run, err = ReadDocuments(context.Background(), g, store, j, g.Assets["colgate.edu"], opts)
	if err != nil {
		t.Fatal(err)
	}
	if run.Read != 1 || run.Skipped != 1 || run.Remaining != 1 || run.Statements != 2 || run.Rejected != 1 {
		t.Fatalf("run %+v", run)
	}
	d := run.Documents[0]
	if d.URL != "https://www.colgate.edu/a.pdf" || d.Category != "staff_directory" || d.ReadingID == "" {
		t.Fatalf("document %+v", d)
	}
	if len(store.props) != 2 {
		t.Fatalf("stored %d properties, want the category and one statement", len(store.props))
	}
	if ids, _ := j.StoredDocumentReadings("f-a"); len(ids) != 1 || ids[0] != d.ReadingID {
		t.Fatalf("journaled readings %v", ids)
	}

	if _, err := ReadDocuments(context.Background(), g, store, j, g.Assets["colgate.edu"],
		DocumentRunOptions{}); err == nil {
		t.Fatal("a run without a document model read documents")
	}
}
