// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// propDocStatement is a statement the document model read from a File's
// passages (see review.PropDocStatement).
const propDocStatement = "doc_statement"

// documentEvidenceLimit bounds the properties read per File: the passages
// (at most 20), the statements and the metadata properties fit well within it.
const documentEvidenceLimit = 200

// DocumentText is one stored File with the passages the documents collector
// kept from it, for the document model to read.
type DocumentText struct {
	FileID   string   `json:"file_id"`
	URL      string   `json:"url"`
	Passages []string `json:"passages"`
	// Statements counts the statements already stored on the File.
	Statements int `json:"statements,omitempty"`
}

// DocumentTexts lists the Files stored from the URLs a domain or organization
// controls that have passages, in URL order. It reads only. The graph must
// return document text as stored: a graph that withholds it from other models
// (oamrepo.Adapter.WithholdDocumentText) gives markers, not passages.
func DocumentTexts(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) ([]DocumentText, error) {
	g = graph.Cached(g)
	s, err := newScope(ctx, g, schema, root, limits, LensDocuments)
	if err != nil {
		return nil, err
	}

	urls, err := s.ownedURLs()
	if err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var out []DocumentText
	for _, u := range urls {
		if s.spent() {
			break
		}
		steps, err := s.w.steps(u)
		if err != nil {
			return out, err
		}
		for _, st := range steps {
			if !st.forward || st.other.Type != "File" || seen[st.other.ID] {
				continue
			}
			seen[st.other.ID] = true

			ev, err := s.w.graph.Evidence(s.w.ctx, st.other.ID, documentEvidenceLimit)
			if err != nil {
				return out, err
			}
			passages := propertyValues(ev, propDocPassage)
			if len(passages) == 0 {
				continue
			}

			url := graph.ContentString(st.other, "url")
			if url == "" {
				url = graph.AssetLabel(st.other)
			}
			out = append(out, DocumentText{
				FileID:     st.other.ID,
				URL:        url,
				Passages:   passages,
				Statements: len(propertyValues(ev, propDocStatement)),
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out, nil
}
