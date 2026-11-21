// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// writeDocumentRun prints a documents run, one line per document read.
func writeDocumentRun(out io.Writer, root string, run ai.DocumentRun) error {
	if len(run.Documents) == 0 && run.Skipped == 0 && run.Remaining == 0 {
		_, err := fmt.Fprintf(out, "no stored documents with passages for %s\n", root)
		return err
	}

	verb := "stored"
	if run.DryRun {
		verb = "would store"
	}
	for _, d := range run.Documents {
		if d.Error != "" {
			_, _ = fmt.Fprintf(out, "%s: %s\n", d.URL, d.Error)
			continue
		}
		category := d.Category
		if category == "" {
			category = "none"
		}
		_, _ = fmt.Fprintf(out, "%s: %s %d statements (category %s), rejected %d", d.URL, verb, d.Statements,
			category, d.Rejected)
		if d.ReadingID != "" {
			_, _ = fmt.Fprintf(out, " [%s]", d.ReadingID)
		}
		_, _ = fmt.Fprintln(out)
		// a dry run shows what would be stored, quotes included
		if run.DryRun {
			for _, s := range d.Stored {
				_, _ = fmt.Fprintf(out, "    %s %s %s", s.Subject, s.Predicate, s.Object)
				if s.Detail != "" {
					_, _ = fmt.Fprintf(out, " (%s)", s.Detail)
				}
				if s.Quote != "" {
					_, _ = fmt.Fprintf(out, ": %q", s.Quote)
				}
				_, _ = fmt.Fprintln(out)
			}
		}
	}

	_, err := fmt.Fprintf(out, "read %d documents, skipped %d already read, %d remaining, failed %d: "+
		"%d statements, %d rejected\n", run.Read, run.Skipped, run.Remaining, run.Failed, run.Statements, run.Rejected)
	return err
}
