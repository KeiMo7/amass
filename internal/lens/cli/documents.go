// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// retractDocument retracts a lead the document model gave an enumeration, or
// undoes a stored document reading, by its journal ID.
func retractDocument(ctx context.Context, w review.DocumentLeadStore, journalPath, id, reviewer string,
	out io.Writer) error {
	j := &review.Journal{Path: journalPath}
	if review.IsDocumentReading(id) {
		if err := review.UndoDocumentStatements(ctx, w, j, id, reviewer); err != nil {
			return err
		}
		_, err := fmt.Fprintf(out, "Undid document reading %s: its statements were removed.\n", id)
		return err
	}

	removed, err := review.RetractDocumentLead(ctx, w, j, id, reviewer)
	if err != nil {
		return err
	}
	if removed {
		_, err = fmt.Fprintf(out, "Retracted %s: the asset was removed (the engine had linked nothing to it).\n", id)
	} else {
		_, err = fmt.Fprintf(out, "Retracted %s: the amass-ai tags were removed; the asset stays, since the "+
			"engine linked other assets to it.\n", id)
	}
	return err
}

// isDocumentDecision reports whether id names a document lead or reading.
func isDocumentDecision(id string) bool {
	return review.IsDocumentLead(id) || review.IsDocumentReading(id)
}

// footprintText describes what the engine collected from a confirmed lead.
func footprintText(fp *review.LeadFootprint) string {
	if len(fp.Assets) == 0 {
		return fmt.Sprintf("Confirmed: %d relation(s) touch it.", fp.Relations)
	}
	kinds := make([]string, 0, len(fp.Assets))
	for k := range fp.Assets {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%d %s", fp.Assets[k], k))
	}
	more := ""
	if fp.Truncated {
		more = " (more beyond the walk)"
	}
	return fmt.Sprintf("Confirmed; it led to %s over %d relation(s)%s.", strings.Join(parts, ", "), fp.Relations, more)
}
