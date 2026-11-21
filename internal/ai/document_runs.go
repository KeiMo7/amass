// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// DocumentRootGraph resolves a domain name or an organization name to a
// stored asset.
type DocumentRootGraph interface {
	graph.AssetResolver
	graph.OrgSearchGraph
}

// DocumentRoot resolves the domain or organization whose documents are read.
func DocumentRoot(ctx context.Context, g DocumentRootGraph, domain, org string) (graph.Asset, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	org = strings.TrimSpace(org)
	switch {
	case domain != "" && org != "":
		return graph.Asset{}, errors.New("give a domain or an organization, not both")
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
				"resolve the organization first", org)
		}
		return *res.Match, nil
	}
	return graph.Asset{}, errors.New("a domain or an organization is required: whose documents to read")
}

// DocumentRunOptions are the settings of one documents run.
type DocumentRunOptions struct {
	Model        llm.Model
	ModelID      string
	ModelTimeout time.Duration
	// Max bounds the documents read in one run; 0 reads them all.
	Max int
	// Reread reads documents that already have stored statements again,
	// undoing their earlier readings first.
	Reread bool
	// DryRun reads and validates but stores nothing.
	DryRun bool
	// Actor is who undoes earlier readings when Reread is set.
	Actor string
	// Schema gives the relationship semantics the documents are found by;
	// nil uses the OAM catalog.
	Schema graph.SchemaCatalog
}

// DocumentResult is what one run did with one document. It holds counts, not
// document text, so it can be shown to any client.
type DocumentResult struct {
	URL        string `json:"url"`
	FileID     string `json:"file_id"`
	Category   string `json:"category,omitempty"`
	Statements int    `json:"statements"`
	Rejected   int    `json:"rejected,omitempty"`
	ReadingID  string `json:"reading_id,omitempty"`
	Error      string `json:"error,omitempty"`
	// Stored is what was (or, in a dry run, would be) stored; it quotes the
	// document, so callers show it only where document text may be shown.
	Stored []review.StoredStatement `json:"-"`
}

// DocumentRun is the outcome of one documents run.
type DocumentRun struct {
	Documents  []DocumentResult `json:"documents"`
	Read       int              `json:"read"`
	Skipped    int              `json:"skipped"`
	Remaining  int              `json:"remaining"`
	Failed     int              `json:"failed"`
	Statements int              `json:"statements"`
	Rejected   int              `json:"rejected"`
	DryRun     bool             `json:"dry_run,omitempty"`
}

// ReadDocuments has the document model read the passages of the documents the
// root publishes, and stores the statements that pass validation on each File
// as doc_statement properties, journaled so each reading can be undone.
// Documents already read are skipped unless opts.Reread is set; documents past
// opts.Max are counted as Remaining, so another run continues where this one
// stopped. g must return document text as stored.
func ReadDocuments(ctx context.Context, g graph.Graph, store review.DocumentStatementStore, j *review.Journal,
	root graph.Asset, opts DocumentRunOptions) (DocumentRun, error) {
	run := DocumentRun{DryRun: opts.DryRun}
	if opts.Model == nil {
		return run, errors.New("no document model is configured (ai.documents)")
	}
	if opts.ModelTimeout <= 0 {
		opts.ModelTimeout = DefaultDocumentModelTimeout
	}
	if opts.Actor == "" {
		opts.Actor = review.InferenceSource + " (reread)"
	}

	if opts.Schema == nil {
		opts.Schema = oamrepo.Catalog{}
	}

	docs, err := lens.DocumentTexts(ctx, g, opts.Schema, root, lens.LensLimits{})
	if err != nil {
		return run, err
	}

	for _, d := range docs {
		if ctx.Err() != nil {
			return run, ctx.Err()
		}
		if d.Statements > 0 && !opts.Reread {
			run.Skipped++
			continue
		}
		if opts.Max > 0 && run.Read+run.Failed >= opts.Max {
			run.Remaining++
			continue
		}

		res := DocumentResult{URL: d.URL, FileID: d.FileID}
		dctx, cancel := context.WithTimeout(ctx, opts.ModelTimeout)
		reading, err := ReadDocument(dctx, opts.Model, opts.ModelID, d.URL, d.Passages)
		cancel()
		if err != nil {
			run.Failed++
			res.Error = err.Error()
			run.Documents = append(run.Documents, res)
			continue
		}

		run.Read++
		res.Category, res.Rejected, res.Stored = reading.Category, len(reading.Rejected), reading.Stored(d.URL)
		res.Statements = len(res.Stored)
		if !opts.DryRun {
			if opts.Reread {
				if err := undoReadings(ctx, store, j, d.FileID, opts.Actor); err != nil {
					return run, err
				}
			}
			rec, err := review.StoreDocumentStatements(ctx, store, j, d.FileID, d.URL, opts.ModelID, res.Stored)
			if err != nil {
				return run, err
			}
			res.ReadingID = rec.ID
		}
		run.Statements += res.Statements
		run.Rejected += res.Rejected
		run.Documents = append(run.Documents, res)
	}

	return run, nil
}

// undoReadings undoes the stored readings of a File before it is read again.
func undoReadings(ctx context.Context, store review.DocumentStatementStore, j *review.Journal, fileID,
	actor string) error {
	ids, err := j.StoredDocumentReadings(fileID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := review.UndoDocumentStatements(ctx, store, j, id, actor); err != nil {
			return err
		}
	}
	return nil
}
