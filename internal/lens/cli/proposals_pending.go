// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// PendingSummary counts the proposals in a journal that are still awaiting a
// decision, grouped by kind. It lets a finished enumeration, or any client
// polling a run, tell the user how many proposals are waiting and of what kind
// without their having to run `amass review proposals` — closing the gap where
// proposals surfaced only to someone who knew to look.
type PendingSummary struct {
	Ownership   int `json:"ownership"`
	Merges      int `json:"merges"`
	Identities  int `json:"identities"`
	PersonNamed int `json:"person_named"`
	Relations   int `json:"relations"`
	Total       int `json:"total"`
}

// PendingProposalsSummary counts, by kind, the journal's proposals that are
// still awaiting a decision. It reads the same journal `amass review` reads, so
// its counts match what a review session would show.
func PendingProposalsSummary(journalPath string) (PendingSummary, error) {
	return PendingProposalsSince(journalPath, time.Time{})
}

// PendingProposalsSince counts, by kind, the proposals still awaiting a
// decision that were recorded at or after since, so a run reports the
// proposals it raised rather than the whole journal's backlog. A zero since
// counts them all. A proposal recorded without a time is counted only then.
func PendingProposalsSince(journalPath string, since time.Time) (PendingSummary, error) {
	var s PendingSummary
	if journalPath == "" {
		return s, errors.New("-journal required")
	}

	j := &review.Journal{Path: journalPath}
	entries, err := j.OwnershipEntries()
	if err != nil {
		return s, err
	}
	merges, err := j.DuplicateEntries()
	if err != nil {
		return s, err
	}
	identities, err := j.IdentityEntries()
	if err != nil {
		return s, err
	}
	people, err := j.PersonNamedEntries()
	if err != nil {
		return s, err
	}
	relations, err := j.RelationEntries("")
	if err != nil {
		return s, err
	}

	recent := func(at time.Time) bool { return since.IsZero() || !at.Before(since) }
	for _, e := range filterPendingOwnership(entries) {
		if recent(e.Proposal.CreatedAt) {
			s.Ownership++
		}
	}
	for _, e := range filterPendingDuplicate(merges) {
		if recent(e.Proposal.CreatedAt) {
			s.Merges++
		}
	}
	for _, e := range filterPendingIdentity(identities) {
		if recent(e.Proposal.CreatedAt) {
			s.Identities++
		}
	}
	for _, e := range filterPendingPersonNamed(people) {
		if recent(e.Proposal.CreatedAt) {
			s.PersonNamed++
		}
	}
	for _, e := range filterPendingRelation(relations) {
		if recent(e.Proposal.CreatedAt) {
			s.Relations++
		}
	}
	s.Total = s.Ownership + s.Merges + s.Identities + s.PersonNamed + s.Relations
	return s, nil
}

// Line renders the summary as a single sentence that names the counts by kind
// and points at the review command, or "" when nothing is pending (so a caller
// can print it only when there is something to say).
func (s PendingSummary) Line() string {
	if s.Total == 0 {
		return ""
	}

	var parts []string
	if s.Merges > 0 {
		parts = append(parts, fmt.Sprintf("%d possible duplicate %s", s.Merges,
			plural(s.Merges, "organization", "organizations")))
	}
	if s.Identities > 0 {
		parts = append(parts, fmt.Sprintf("%d identity %s", s.Identities,
			plural(s.Identities, "correction", "corrections")))
	}
	if s.PersonNamed > 0 {
		parts = append(parts, fmt.Sprintf("%d %s recorded under a person's name", s.PersonNamed,
			plural(s.PersonNamed, "organization", "organizations")))
	}
	if s.Ownership > 0 {
		parts = append(parts, fmt.Sprintf("%d ownership %s", s.Ownership,
			plural(s.Ownership, "relationship", "relationships")))
	}
	if s.Relations > 0 {
		parts = append(parts, fmt.Sprintf("%d inferred %s", s.Relations,
			plural(s.Relations, "relationship", "relationships")))
	}

	return fmt.Sprintf("%d proposal(s) awaiting review: %s — review with 'amass review proposals'",
		s.Total, strings.Join(parts, ", "))
}

// plural picks the singular or plural noun for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
