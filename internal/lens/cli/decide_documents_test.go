// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// A lead the document model gave a run is counted and listed with the other
// changes the AI applied on its own; a retracted one is not.
func TestDocumentLeadsAreAppliedDecisions(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	lead := func(id, status, reviewer string) string {
		data, _ := json.Marshal(map[string]any{"kind": "doc_lead", "data": review.DocumentLead{
			ID: id, RunID: "run1", EntityID: "e-" + id, Name: "Acme Dining Inc.", URL: "https://a.example/x.pdf",
			Predicate: "supplied_by", Model: "ollama/qwen3:8b", Status: status, Reviewer: reviewer,
			At: time.Now().UTC()}})
		return string(data) + "\n"
	}
	content := lead("doclead:run1:a", review.ProposalApplied, review.DocumentLeadReviewer) +
		lead("doclead:run1:b", review.ProposalApplied, review.DocumentLeadReviewer) +
		lead("doclead:run1:b", review.ProposalRetracted, "jeff")
	if err := os.WriteFile(journal, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := AppliedByAISummary(journal, time.Time{})
	if err != nil || s.DocumentLeads != 1 || s.Total != 1 {
		t.Fatalf("summary %+v, %v", s, err)
	}
	if !strings.Contains(s.Line(), "1 document lead") {
		t.Errorf("line %q", s.Line())
	}

	items, err := DecisionItems(journal)
	if err != nil {
		t.Fatal(err)
	}
	var leads []DecisionItem
	for _, d := range items {
		if d.Kind == "document_lead" {
			leads = append(leads, d)
		}
	}
	if len(leads) != 1 || leads[0].ID != "doclead:run1:a" || leads[0].Status != DecisionApplied ||
		!strings.Contains(leads[0].Summary, "Acme Dining Inc.") {
		t.Fatalf("document lead items %+v", leads)
	}
	fp := footprintText(&review.LeadFootprint{Assets: map[string]int{"IPAddress": 2, "FQDN": 1}, Relations: 4})
	if fp != "Confirmed; it led to 1 FQDN, 2 IPAddress over 4 relation(s)." {
		t.Errorf("footprint %q", fp)
	}
	if !isDocumentDecision("doclead:run1:a") || !isDocumentDecision("doc:f1:2026") || isDocumentDecision("acct-1") {
		t.Error("document decision IDs are not recognized")
	}
}
