// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// AppliedSummary counts, by kind, the graph changes the AI classifier applied
// automatically (a reviewer beginning "amass-ai"), so what the classifier did
// without a human in the loop can be surfaced. It is the applied-decision
// counterpart of PendingSummary.
type AppliedSummary struct {
	Ownership       int `json:"ownership"`
	Merges          int `json:"merges"`
	Identities      int `json:"identities"`
	ScopeExpansions int `json:"scope_expansions"`
	DocumentLeads   int `json:"document_leads"`
	Total           int `json:"total"`
}

// isAIReviewer reports whether a journal reviewer is the automatic classifier
// (the automatic attribution reviewer or a named model), not a human.
func isAIReviewer(reviewer string) bool {
	return strings.HasPrefix(reviewer, "amass-ai")
}

// AppliedByAISummary counts the decisions the AI classifier applied to the graph
// — ownership edges, organization merges, identity corrections and scope
// expansions — whose latest outcome is applied by an automatic reviewer. When
// since is non-zero only decisions applied at or after it are counted, so a
// caller can report just the current run. It reads the same journal that
// "amass review" reads.
func AppliedByAISummary(journalPath string, since time.Time) (AppliedSummary, error) {
	var s AppliedSummary
	if journalPath == "" {
		return s, errors.New("-journal required")
	}

	applied := func(status, reviewer string, at time.Time) bool {
		return status == review.ProposalApplied && isAIReviewer(reviewer) &&
			(since.IsZero() || !at.Before(since))
	}

	j := &review.Journal{Path: journalPath}

	owned, err := j.OwnershipEntries()
	if err != nil {
		return s, err
	}
	for _, e := range owned {
		if e.Outcome != nil && applied(e.Status, e.Outcome.Reviewer, e.Outcome.At) {
			s.Ownership++
		}
	}

	merges, err := j.DuplicateEntries()
	if err != nil {
		return s, err
	}
	for _, e := range merges {
		if e.Outcome != nil && applied(e.Status, e.Outcome.Reviewer, e.Outcome.At) {
			s.Merges++
		}
	}

	identities, err := j.IdentityEntries()
	if err != nil {
		return s, err
	}
	for _, e := range identities {
		if e.Outcome != nil && applied(e.Status, e.Outcome.Reviewer, e.Outcome.At) {
			s.Identities++
		}
	}

	expansions, err := j.AppliedScopeExpansions()
	if err != nil {
		return s, err
	}
	for _, e := range expansions {
		if applied(e.Status, e.Reviewer, e.At) {
			s.ScopeExpansions++
		}
	}

	leads, err := j.DocumentLeads()
	if err != nil {
		return s, err
	}
	for _, l := range leads {
		if applied(l.Status, l.Reviewer, l.At) {
			s.DocumentLeads++
		}
	}

	s.Total = s.Ownership + s.Merges + s.Identities + s.ScopeExpansions + s.DocumentLeads
	return s, nil
}

// Line renders the applied summary as one sentence naming the counts by kind and
// pointing at the review command, or "" when the classifier applied nothing (so
// a caller prints it only when there is something to say).
func (s AppliedSummary) Line() string {
	if s.Total == 0 {
		return ""
	}

	var parts []string
	if s.Ownership > 0 {
		parts = append(parts, fmt.Sprintf("%d ownership %s", s.Ownership,
			plural(s.Ownership, "relationship", "relationships")))
	}
	if s.Merges > 0 {
		parts = append(parts, fmt.Sprintf("%d organization %s", s.Merges,
			plural(s.Merges, "merge", "merges")))
	}
	if s.Identities > 0 {
		parts = append(parts, fmt.Sprintf("%d identity %s", s.Identities,
			plural(s.Identities, "correction", "corrections")))
	}
	if s.ScopeExpansions > 0 {
		parts = append(parts, fmt.Sprintf("%d scope %s", s.ScopeExpansions,
			plural(s.ScopeExpansions, "expansion", "expansions")))
	}
	if s.DocumentLeads > 0 {
		parts = append(parts, fmt.Sprintf("%d document %s", s.DocumentLeads,
			plural(s.DocumentLeads, "lead", "leads")))
	}

	return fmt.Sprintf("%d change(s) the AI made automatically: %s — review with 'amass review applied'",
		s.Total, strings.Join(parts, ", "))
}

// listApplied reports the changes the AI classifier applied to the graph
// (amass review applied), the applied-decision counterpart of the pending
// proposals listing. A detailed per-item view with evidence is surfaced through
// the MCP list and the end-of-run summary; this prints the by-kind counts.
func listApplied(journalPath, format string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	s, err := AppliedByAISummary(journalPath, time.Time{})
	if err != nil {
		return err
	}
	if format == "json" {
		return writeJSON(out, s)
	}

	line := s.Line()
	if line == "" {
		line = "the AI classifier has applied no changes"
	}
	_, err = fmt.Fprintln(out, line)
	return err
}

// AppliedProposalsText lists, for the MCP list, each change the AI classifier
// applied to the graph on its own, with the same detail "amass review" shows —
// the applied counterpart of PendingProposalsText. (enumeration_status gives
// the counts; this gives the items.)
func AppliedProposalsText(journalPath string) (string, error) {
	return AppliedProposalsTextLive(journalPath, nil)
}

// AppliedProposalsTextLive is AppliedProposalsText, leaving out the changes
// whose entities exists says are gone.
func AppliedProposalsTextLive(journalPath string, exists EntityExists) (string, error) {
	items, err := DecisionItems(journalPath)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	n := 0
	for _, d := range items {
		if d.Status != DecisionApplied || !live(exists, d.EntityIDs...) {
			continue
		}

		n++
		fmt.Fprintf(&b, "\n%s %s (applied by %s)\n%s\n", d.Kind, d.ID, d.Reviewer, d.Summary)
	}
	if n == 0 {
		return "The AI classifier has applied no changes.", nil
	}

	return fmt.Sprintf("%d change(s) the AI classifier applied automatically:\n", n) + b.String(), nil
}
