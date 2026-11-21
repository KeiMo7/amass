// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// docModel replies with each text in turn and records what it was sent.
type docModel struct {
	replies   []string
	histories [][]llm.Message
}

func (m *docModel) Generate(_ context.Context, h []llm.Message, _ []llm.ToolSpec) (llm.Response, error) {
	m.histories = append(m.histories, h)
	return llm.Response{Text: m.replies[min(len(m.histories)-1, len(m.replies)-1)]}, nil
}

var docPassages = []string{
	"The Herkimer College Foundation is a division of Herkimer County Community College.",
	"Jane Doe, Chief Information Officer at Herkimer County Community College, oversees IT.",
}

// Statements that quote a passage exactly, use a catalog predicate with fitting
// types and name both ends in that passage are kept; the rest are rejected.
func TestReadDocumentValidates(t *testing.T) {
	reply := `{"category": "staff_directory", "statements": [
	 {"subject": "Herkimer College Foundation", "subject_type": "Organization", "predicate": "unit_of",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "The Herkimer College Foundation is a division of Herkimer County Community College."},
	 {"subject": "Jane Doe", "subject_type": "Person", "predicate": "holds_role",
	  "object": "Herkimer County Community College", "object_type": "Organization", "detail": "Chief Information Officer",
	  "quote": "Jane Doe, Chief Information Officer at Herkimer County Community College"},
	 {"subject": "Herkimer College Foundation", "subject_type": "Organization", "predicate": "unit_of",
	  "object": "SUNY", "object_type": "Organization",
	  "quote": "The Herkimer College Foundation is a division of Herkimer County Community College."},
	 {"subject": "Jane Doe", "subject_type": "Person", "predicate": "acquired_by",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "Jane Doe, Chief Information Officer"},
	 {"subject": "Acme", "subject_type": "Organization", "predicate": "supplied_by",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "Acme supplies the College"},
	 {"subject": "Jane Doe", "subject_type": "Person", "predicate": "owns_everything",
	  "object": "Herkimer County Community College", "object_type": "Organization",
	  "quote": "Jane Doe, Chief Information Officer"}
	]}`
	model := &docModel{replies: []string{reply}}

	r, err := ReadDocument(context.Background(), model, "test-model", "https://herkimer.edu/a.pdf", docPassages)
	if err != nil {
		t.Fatal(err)
	}
	if r.Category != "staff_directory" {
		t.Errorf("category %q", r.Category)
	}
	if len(r.Statements) != 2 {
		t.Fatalf("kept %d statements: %+v (rejected %q)", len(r.Statements), r.Statements, r.Rejected)
	}
	if s := r.Statements[1]; s.Predicate != "holds_role" || s.Detail != "Chief Information Officer" || s.Model != "test-model" {
		t.Errorf("role statement %+v", s)
	}
	if len(r.Rejected) != 4 {
		t.Errorf("rejected %q", r.Rejected)
	}
	for _, want := range []string{"not named in the quoted passage", "does not take", "not in any passage", "unknown predicate"} {
		if !strings.Contains(strings.Join(r.Rejected, "|"), want) {
			t.Errorf("no rejection for %q in %q", want, r.Rejected)
		}
	}
}

// An unknown category is dropped, a fenced reply is read, and no passages
// means no model call.
func TestReadDocumentEdges(t *testing.T) {
	model := &docModel{replies: []string{"```json\n{\"category\": \"poem\", \"statements\": []}\n```"}}
	r, err := ReadDocument(context.Background(), model, "m", "u", docPassages)
	if err != nil || r.Category != "" || len(r.Statements) != 0 {
		t.Errorf("reading %+v, %v", r, err)
	}

	idle := &docModel{}
	if _, err := ReadDocument(context.Background(), idle, "m", "u", nil); err != nil || len(idle.histories) != 0 {
		t.Errorf("a document without passages called the model: %v", err)
	}
	if _, err := ReadDocument(context.Background(), nil, "m", "u", docPassages); err == nil {
		t.Error("no model was accepted")
	}
}

// The prompt lists every catalog predicate, and the schema allows only them.
func TestDocumentPromptAndSchema(t *testing.T) {
	model := &docModel{replies: []string{`{"category": "other", "statements": []}`}}
	if _, err := ReadDocument(context.Background(), model, "m", "u", docPassages); err != nil {
		t.Fatal(err)
	}
	prompt := model.histories[0][0].Text
	for _, want := range []string{"unit_of", "holds_role", "staff_directory", "copied exactly"} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	if !strings.Contains(model.histories[0][1].Text, "1. The Herkimer College Foundation") {
		t.Error("passages are not numbered in the request")
	}
	var _ llm.Model = model
}

// A reading is stored as its statements plus its category, File is_a
// <category>.
func TestDocumentReadingStored(t *testing.T) {
	r := DocumentReading{Category: "annual_report", Statements: []DocumentStatement{{
		Subject: "SUNY Cobleskill", SubjectType: "Organization", Predicate: "unit_of",
		Object: "State University of New York", ObjectType: "Organization",
		Quote: "SUNY Cobleskill is a campus of the State University of New York.", Model: "ollama/qwen3"}}}
	got := r.Stored("https://www.cobleskill.edu/report.pdf")
	if len(got) != 2 {
		t.Fatalf("stored %d statements, want 2", len(got))
	}
	if c := got[0]; c.Predicate != review.PredicateIsA || c.SubjectType != "File" ||
		c.Subject != "https://www.cobleskill.edu/report.pdf" || c.Object != "annual_report" {
		t.Fatalf("category statement %+v", c)
	}
	if s := got[1]; s.Predicate != "unit_of" || s.Quote == "" || s.Model != "ollama/qwen3" {
		t.Fatalf("statement %+v", s)
	}
	if len((DocumentReading{}).Stored("u")) != 0 {
		t.Fatal("an empty reading stored statements")
	}
}
