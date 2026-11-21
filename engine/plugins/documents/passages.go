// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/docmeta"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	"golang.org/x/net/publicsuffix"
)

// PropPassage is a sentence of the document kept for the statement model: one
// that names something the document links and states a relationship.
const PropPassage = "doc_passage"

// sentenceEnd splits text after a sentence's closing punctuation, or at a
// blank line or a line that ends a paragraph-like block.
var sentenceEnd = regexp.MustCompile(`([.!?])\s+|\n\s*\n|\r?\n[ \t]*[•\-–*]\s`)

// passageLeads keeps the document's sentences that state a relationship, as
// PropPassage properties on the File, for the statement model to read (see
// semantics/statement_cues.json). A sentence is kept when it names one of
// mentions and has a statement cue, or names two of mentions. Kept sentences
// are what the document says, verbatim but for whitespace, so a statement can
// quote one exactly; nothing is concluded here.
func (d *documents) passageLeads(e *et.Event, fent *dbt.Entity, text string, mentions []string, n *leads) {
	passages := selectPassages(semantics.StatementCueRules(), text, mentions)
	if len(passages) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	for _, p := range passages {
		d.property(ctx, e, fent, PropPassage, p)
		n.passages++
	}
}

// selectPassages returns the sentences of text that name one of mentions and
// carry a statement cue, or name two of mentions, in document order, without
// repeats, at most rules.MaxPassages, each at most rules.MaxPassageChars long.
func selectPassages(rules semantics.StatementCues, text string, mentions []string) []string {
	var terms []string
	seenTerm := map[string]bool{}
	for _, m := range mentions {
		m = strings.ToLower(strings.TrimSpace(m))
		// a short term matches inside unrelated words
		if utf8.RuneCountInString(m) < 4 || seenTerm[m] {
			continue
		}
		seenTerm[m] = true
		terms = append(terms, m)
	}
	if len(terms) == 0 {
		return nil
	}

	var out []string
	seen := map[string]bool{}
	for _, s := range splitSentences(text) {
		if len(out) >= rules.MaxPassages {
			break
		}

		lower := strings.ToLower(s)
		named := 0
		first := -1
		for _, t := range terms {
			if i := strings.Index(lower, t); i >= 0 {
				named++
				if first < 0 || i < first {
					first = i
				}
			}
		}
		if named == 0 || (named < 2 && len(rules.Match(s)) == 0) {
			continue
		}

		p := window(s, first, rules.MaxPassageChars)
		if key := strings.ToLower(p); !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// splitSentences splits text into sentences with their whitespace collapsed,
// keeping each sentence's closing punctuation.
func splitSentences(text string) []string {
	var out []string
	last := 0
	for _, m := range sentenceEnd.FindAllStringSubmatchIndex(text, -1) {
		end := m[0]
		if m[2] >= 0 {
			end = m[3] // keep the punctuation
		}
		if s := strings.Join(strings.Fields(text[last:end]), " "); s != "" {
			out = append(out, s)
		}
		last = m[1]
	}
	if s := strings.Join(strings.Fields(text[last:]), " "); s != "" {
		out = append(out, s)
	}
	return out
}

// window returns s when it is at most limit bytes, else about limit bytes of it
// around byte offset at, cut on spaces, so a long run of text without
// punctuation keeps the part that names something.
func window(s string, at, limit int) string {
	if len(s) <= limit {
		return s
	}

	start := max0(at - limit/3)
	end := start + limit
	if end > len(s) {
		end = len(s)
		start = max0(end - limit)
	}
	// never cut inside a character
	for start < end && !utf8.RuneStart(s[start]) {
		start++
	}
	for end < len(s) && !utf8.RuneStart(s[end]) {
		end--
	}
	if start > 0 {
		if i := strings.IndexByte(s[start:end], ' '); i >= 0 {
			start += i + 1
		}
	}
	if end < len(s) {
		if i := strings.LastIndexByte(s[start:end], ' '); i > 0 {
			end = start + i
		}
	}
	return strings.TrimSpace(s[start:end])
}

func max0(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// metadataMentions are the people and organization the metadata names, as
// written, leaving out placeholder values.
func metadataMentions(meta docmeta.Metadata) []string {
	rules := semantics.Documents()

	var out []string
	for _, a := range []string{meta.Author, meta.LastModifiedBy} {
		if a = strings.TrimSpace(a); a != "" && !rules.IsPlaceholderAuthor(a) {
			out = append(out, a)
		}
	}
	if c := strings.TrimSpace(meta.Company); c != "" && !rules.IsPlaceholderCompany(c) &&
		!semantics.IsPlaceholderOrganization(c) {
		out = append(out, c)
	}
	return out
}

// publisherName is the name the publishing domain is registered under, without
// its public suffix ("herkimer" for www.herkimer.edu): prose names the
// organization, rarely its host names, and its name usually carries this word.
func publisherName(host string) string {
	reg, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(host, ".")))
	if err != nil {
		return ""
	}
	label, _, _ := strings.Cut(reg, ".")
	return label
}
