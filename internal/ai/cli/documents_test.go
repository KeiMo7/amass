// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// A run prints one line per document; a dry run also shows what it would
// store, quotes included.
func TestWriteDocumentRun(t *testing.T) {
	run := ai.DocumentRun{Read: 1, Skipped: 2, Remaining: 3, Failed: 1, Statements: 2, Rejected: 1, DryRun: true,
		Documents: []ai.DocumentResult{
			{URL: "https://a.example/plan.pdf", Category: "annual_report", Statements: 2, Rejected: 1,
				Stored: []review.StoredStatement{{Subject: "Foundation", Predicate: "unit_of", Object: "College",
					Quote: "The Foundation is a division of the College."}}},
			{URL: "https://a.example/b.pdf", Error: "model timed out"},
		}}
	var out bytes.Buffer
	if err := writeDocumentRun(&out, "a.example", run); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://a.example/plan.pdf: would store 2 statements (category annual_report), rejected 1",
		`Foundation unit_of College: "The Foundation is a division of the College."`,
		"https://a.example/b.pdf: model timed out",
		"read 1 documents, skipped 2 already read, 3 remaining, failed 1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	_ = writeDocumentRun(&out, "b.example", ai.DocumentRun{})
	if !strings.Contains(out.String(), "no stored documents with passages for b.example") {
		t.Errorf("empty run: %q", out.String())
	}
}
