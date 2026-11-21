// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// defaultDocumentModelTimeout bounds one document model request when
// ai.documents.model_timeout is not set.
const defaultDocumentModelTimeout = 3 * time.Minute

// documentModel builds the model the user named in ai.documents, with its
// name for the statements it reads and its per-request timeout. There is no
// fallback to the main model: without ai.documents no model reads documents.
func documentModel(d *config.DocumentModelSettings) (llm.Model, string, time.Duration, error) {
	if d == nil || !d.Enabled {
		return nil, "", 0, errors.New("no document model is configured: enable ai.documents in the config " +
			"(the main model is never used to read documents)")
	}
	if err := d.Validate(); err != nil {
		return nil, "", 0, err
	}

	timeout := defaultDocumentModelTimeout
	if d.ModelTimeout != "" {
		v, err := time.ParseDuration(d.ModelTimeout)
		if err != nil {
			return nil, "", 0, err
		}
		timeout = v
	}

	var key string
	if d.APIKeyEnv != "" {
		key = os.Getenv(d.APIKeyEnv)
	}
	provider := strings.ToLower(strings.TrimSpace(d.Provider))
	zero := 0.0
	m, err := newProvider(providerSettings{Provider: provider, Endpoint: d.Endpoint, Model: d.Model,
		APIKey: key, AllowHTTP: d.AllowHTTP, Timeout: timeout, Temperature: &zero})
	if err != nil {
		return nil, "", 0, fmt.Errorf("ai.documents: %w", err)
	}
	return m, provider + "/" + d.Model, timeout, nil
}

// rootGraph resolves a domain name or an organization name to a stored asset.
type rootGraph interface {
	graph.AssetResolver
	graph.OrgSearchGraph
}

// documentRoot resolves the domain or organization whose documents are read.
func documentRoot(ctx context.Context, g rootGraph, domain, org string) (graph.Asset, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	org = strings.TrimSpace(org)
	switch {
	case domain != "" && org != "":
		return graph.Asset{}, errors.New("use -domain or -org, not both")
	case domain != "":
		res, err := g.ResolveAsset(ctx, graph.AssetSelector{Type: "FQDN", Field: "name", Value: domain}, 2)
		if err != nil {
			return graph.Asset{}, err
		}
		if len(res.Candidates) != 1 {
			return graph.Asset{}, fmt.Errorf("%s is not a stored domain name", domain)
		}
		return res.Candidates[0].Asset, nil
	case org != "":
		res, err := graph.ResolveOrSuggest(ctx, g, org, 5)
		if err != nil {
			return graph.Asset{}, err
		}
		if res.Status != graph.StatusMatched || res.Match == nil {
			return graph.Asset{}, fmt.Errorf("%q does not name exactly one stored organization; "+
				"use amass lens resolve to find it", org)
		}
		return *res.Match, nil
	}
	return graph.Asset{}, errors.New("-domain or -org required: whose documents to read")
}

// documentOptions are the documents operation's settings.
type documentOptions struct {
	Model        llm.Model
	ModelID      string
	ModelTimeout time.Duration
	// Max bounds the documents read in one run.
	Max int
	// Reread reads documents that already have stored statements again,
	// undoing their earlier readings first.
	Reread bool
	// DryRun reads and validates but stores nothing.
	DryRun bool
}

// documentsSummary is the outcome of one documents run.
type documentsSummary struct {
	Read       int `json:"read"`
	Skipped    int `json:"skipped"`
	Failed     int `json:"failed"`
	Statements int `json:"statements"`
	Rejected   int `json:"rejected"`
}

// readDocuments has the document model read the passages of the documents the
// root publishes, and stores the statements that pass validation on each File
// as doc_statement properties, journaled so each reading can be undone.
// Documents already read are skipped unless opts.Reread is set.
func readDocuments(ctx context.Context, out io.Writer, g graph.Graph, store review.DocumentStatementStore,
	j *review.Journal, root graph.Asset, opts documentOptions) (documentsSummary, error) {
	var sum documentsSummary
	docs, err := lens.DocumentTexts(ctx, g, oamrepo.Catalog{}, root, lens.LensLimits{})
	if err != nil {
		return sum, err
	}
	if len(docs) == 0 {
		_, _ = fmt.Fprintf(out, "no stored documents with passages for %s\n", graph.AssetLabel(root))
		return sum, nil
	}

	for _, d := range docs {
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		if opts.Max > 0 && sum.Read >= opts.Max {
			sum.Skipped++
			continue
		}
		if d.Statements > 0 && !opts.Reread {
			sum.Skipped++
			continue
		}

		dctx, cancel := context.WithTimeout(ctx, opts.ModelTimeout)
		reading, err := ai.ReadDocument(dctx, opts.Model, opts.ModelID, d.URL, d.Passages)
		cancel()
		if err != nil {
			sum.Failed++
			_, _ = fmt.Fprintf(out, "%s: %v\n", d.URL, err)
			continue
		}
		sum.Read++
		sum.Rejected += len(reading.Rejected)
		stored := reading.Stored(d.URL)

		verb := "would store"
		if !opts.DryRun {
			verb = "stored"
			if opts.Reread {
				if err := undoReadings(ctx, store, j, d.FileID); err != nil {
					return sum, err
				}
			}
			if _, err := review.StoreDocumentStatements(ctx, store, j, d.FileID, d.URL, opts.ModelID,
				stored); err != nil {
				return sum, err
			}
		}
		sum.Statements += len(stored)
		_, _ = fmt.Fprintf(out, "%s: %s %d statements (category %s), rejected %d\n", d.URL, verb, len(stored),
			orNone(reading.Category), len(reading.Rejected))
	}

	_, _ = fmt.Fprintf(out, "read %d documents, skipped %d, failed %d: %d statements, %d rejected\n",
		sum.Read, sum.Skipped, sum.Failed, sum.Statements, sum.Rejected)
	return sum, nil
}

// undoReadings undoes the stored readings of a File before it is read again.
func undoReadings(ctx context.Context, store review.DocumentStatementStore, j *review.Journal, fileID string) error {
	ids, err := j.StoredDocumentReadings(fileID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := review.UndoDocumentStatements(ctx, store, j, id, review.InferenceSource+" (reread)"); err != nil {
			return err
		}
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
