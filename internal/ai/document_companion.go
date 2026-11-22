// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// Document companion defaults.
const (
	// DefaultDocumentInterval is the time between the companion's passes.
	DefaultDocumentInterval = 30 * time.Second
	// DefaultDocumentBatch is how many documents one pass reads per target.
	DefaultDocumentBatch = 3
)

// Activity names the companion counts in a run's Activity.
const (
	ActivityDocumentsRead    = "documents_read"
	ActivityDocumentFailures = "document_failures"
	// ActivityDocumentErrors counts passes that could not list a target's
	// documents (a database or lens error), which would otherwise be silent.
	ActivityDocumentErrors = "document_errors"
	ActivityStatements     = "statements"
	// ActivityChunksRead counts the chunks of documents read, so a long
	// document shows progress before it is finished.
	ActivityChunksRead   = "chunks_read"
	ActivityLeads        = "leads"
	ActivityLeadsWaiting = "leads_waiting"
)

// DocumentGraph is the graph the companion reads documents from: it must
// return document text as stored (no withholding) and resolve the run's
// targets.
type DocumentGraph interface {
	graph.Graph
	DocumentRootGraph
}

// DocumentCompanion has the document model read the documents a supervised
// enumeration collects while it runs, all of each document's text, stores the
// validated findings as a documents run does, and hands each asset they name
// that the engine collects from (domains, addresses, networks, organizations,
// street addresses, phones, emails, URLs) and the database does not hold to
// the run's session as a lead. The engine checks
// a lead like any other (registries, attribution); it joins the scope only if
// the engine attributes it to the target. Each lead is tagged amass-ai and
// journaled so it can be retracted. The engine itself uses no model.
type DocumentCompanion struct {
	Graph        DocumentGraph
	Store        review.DocumentLeadStore
	Journal      *review.Journal
	Model        llm.Model
	ModelID      string
	ModelTimeout time.Duration
	// Interval is the time between passes; Batch the documents read per
	// target in one pass; ChunkChars the text one model request reads.
	Interval   time.Duration
	Batch      int
	ChunkChars int
	// Fetcher gets a document's text; nil fetches it over HTTP.
	Fetcher DocumentFetcher
	// MaxLeads caps the adaptive lead budget (see allowance): 0 leaves it to
	// the confirmation rate and the run's size, a negative value submits no
	// leads (findings are still stored).
	MaxLeads int
	// Schema gives the relationship semantics; nil uses the OAM catalog.
	Schema graph.SchemaCatalog
}

// companionRun is the companion's state for one run.
type companionRun struct {
	mu        sync.Mutex
	inPass    bool
	remaining int
	lastStart time.Time
	doneAt    time.Time
	nudge     chan struct{}
	roots     map[string]graph.Asset
	seen      map[string]bool
	submitted []*submittedLead
	queue     []queuedLead
}

// Begin implements collect.Companion.
func (c *DocumentCompanion) Begin(ctx context.Context, run collect.Run, act collect.Activity) func() bool {
	if c == nil || c.Model == nil || c.Graph == nil || c.Store == nil || c.Journal == nil {
		return nil
	}

	st := &companionRun{nudge: make(chan struct{}, 1), roots: map[string]graph.Asset{}, seen: map[string]bool{}}
	interval := c.Interval
	if interval <= 0 {
		interval = DefaultDocumentInterval
	}

	go func() {
		tick := time.NewTicker(interval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			case <-st.nudge:
			}
			c.pass(ctx, run, act, st)
		}
	}()

	// Pending: a pass is running, documents remain unread, or no pass has
	// started since the engine finished its work (the first call), so the
	// documents collected last are read before the run ends.
	return func() bool {
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.doneAt.IsZero() {
			st.doneAt = time.Now()
			select {
			case st.nudge <- struct{}{}:
			default:
			}
		}
		return st.inPass || st.remaining > 0 || !st.lastStart.After(st.doneAt)
	}
}

// Finish implements collect.Finisher: when the run ends, each lead it was
// given is settled. One the engine linked to other assets, or another source
// reported, is kept and the relations it led to cite the document; any other
// is retracted as expired.
func (c *DocumentCompanion) Finish(ctx context.Context, run collect.Run) {
	if c == nil || c.Store == nil || c.Journal == nil {
		return
	}
	_, _, _ = review.SettleDocumentLeads(ctx, c.Store, c.Journal, run.ID)
}

// documentTargets returns the domains a run collects.
func documentTargets(run collect.Run) []string {
	var out []string
	if run.Plan.ScopeType == "domain" && run.Plan.ScopeValue != "" {
		out = append(out, run.Plan.ScopeValue)
	}
	for _, e := range run.Plan.Also {
		if e.Type == "domain" && e.Value != "" {
			out = append(out, e.Value)
		}
	}
	return out
}

// pass reads the next unread documents of each of the run's targets and
// submits the leads their statements give.
func (c *DocumentCompanion) pass(ctx context.Context, run collect.Run, act collect.Activity, st *companionRun) {
	st.mu.Lock()
	st.inPass, st.lastStart = true, time.Now()
	st.mu.Unlock()

	remaining := 0
	defer func() {
		st.mu.Lock()
		st.inPass, st.remaining = false, remaining
		st.mu.Unlock()
	}()

	// confirmations since the last pass may have raised the budget
	c.drain(ctx, run, act, st)

	batch := c.Batch
	if batch <= 0 {
		batch = DefaultDocumentBatch
	}
	for _, domain := range documentTargets(run) {
		if ctx.Err() != nil {
			return
		}

		root, ok := st.roots[domain]
		if !ok {
			r, err := DocumentRoot(ctx, c.Graph, domain, "")
			if err != nil {
				// not stored yet early in a run; try again next pass
				continue
			}
			root, st.roots[domain] = r, r
		}

		res, err := ReadDocuments(ctx, c.Graph, c.Store, c.Journal, root, DocumentRunOptions{Model: c.Model,
			ModelID: c.ModelID, ModelTimeout: c.ModelTimeout, ChunkChars: c.ChunkChars, Max: batch,
			Fetcher: c.Fetcher, Schema: c.Schema, OnChunk: func() { count(act, ActivityChunksRead, 1) }})
		if err != nil {
			if ctx.Err() == nil {
				count(act, ActivityDocumentErrors, 1)
			}
			continue
		}
		count(act, ActivityDocumentsRead, res.Read)
		count(act, ActivityDocumentFailures, res.Failed)
		count(act, ActivityStatements, res.Statements)
		// a model that fails every document is unavailable: do not hold the
		// run open waiting for it
		if res.Read > 0 || res.Failed == 0 {
			remaining += res.Remaining
		}

		for _, d := range res.Documents {
			c.submitLeads(ctx, run, act, st, d)
		}
	}
}

// submitLeads queues the assets a document's findings name that the database
// does not hold, and submits as many as the run's lead budget allows.
func (c *DocumentCompanion) submitLeads(ctx context.Context, run collect.Run, act collect.Activity,
	st *companionRun, d DocumentResult) {
	if c.MaxLeads < 0 || act.Submit == nil {
		return
	}

	anchored := anchoredOrganizations(d.Stored)
	for _, s := range d.Stored {
		for _, l := range statementLeads(s) {
			// before seen: a later document may tie the organization to an
			// anchor
			if !anchoredLead(l, anchored) {
				continue
			}
			key := strings.ToLower(string(l.asset.AssetType()) + "\x00" + l.name)
			if st.seen[key] {
				continue
			}
			st.seen[key] = true
			if knownLead(ctx, c.Graph, l) {
				continue
			}
			st.queue = append(st.queue, queuedLead{lead: l, stmt: s, doc: d})
			count(act, ActivityLeadsWaiting, 1)
		}
	}
	c.drain(ctx, run, act, st)
}

// leadPredicate names how a finding named its lead.
func leadPredicate(s review.StoredStatement) string {
	switch {
	case s.Predicate != "":
		return s.Predicate
	case s.Field != "":
		return "field:" + s.Field
	}
	return "named"
}

func count(act collect.Activity, name string, n int) {
	if n != 0 && act.Count != nil {
		act.Count(name, n)
	}
}
