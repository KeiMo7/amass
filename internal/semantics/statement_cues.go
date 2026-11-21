// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// StatementKind is a kind of statement a document may make, with the
// inference families that may consume such statements and the vocabulary term
// it follows.
type StatementKind struct {
	Families []string `json:"families"`
	Basis    string   `json:"basis"`
}

// StatementCue is a phrase that marks a sentence as stating a relationship.
type StatementCue struct {
	Phrase string   `json:"phrase"`
	Kinds  []string `json:"kinds"`
	re     *regexp.Regexp
}

// StatementCues say which sentences of a collected document are kept as
// passages for the statement model. Loaded from statement_cues.json; see that
// file's _about.
type StatementCues struct {
	License         string                   `json:"_license"`
	About           string                   `json:"_about"`
	MaxPassages     int                      `json:"max_passages"`
	MaxPassageChars int                      `json:"max_passage_chars"`
	Kinds           map[string]StatementKind `json:"kinds"`
	Cues            []StatementCue           `json:"cues"`
}

var loadStatementCues = sync.OnceValue(func() StatementCues {
	var c StatementCues
	dec := json.NewDecoder(bytes.NewReader(File("statement_cues.json")))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		panic("statement_cues.json: " + err.Error())
	}
	if c.MaxPassages <= 0 || c.MaxPassageChars < 80 || len(c.Kinds) == 0 || len(c.Cues) == 0 {
		panic("statement_cues.json: max_passages, max_passage_chars (80 or more), kinds and cues are required")
	}
	for name, k := range c.Kinds {
		if len(k.Families) == 0 || !strings.HasPrefix(k.Basis, "https://") {
			panic("statement_cues.json: kind " + name + " needs families and an https basis")
		}
	}

	seen := map[string]bool{}
	for i := range c.Cues {
		cue := &c.Cues[i]
		phrase := strings.ToLower(strings.TrimSpace(cue.Phrase))
		if phrase == "" || seen[phrase] || len(cue.Kinds) == 0 {
			panic("statement_cues.json: cue " + cue.Phrase + " is empty, repeated or has no kinds")
		}
		seen[phrase] = true
		for _, k := range cue.Kinds {
			if _, ok := c.Kinds[k]; !ok {
				panic("statement_cues.json: cue " + cue.Phrase + " names an unknown kind " + k)
			}
		}
		words := strings.Fields(phrase)
		for j, w := range words {
			words[j] = regexp.QuoteMeta(w)
		}
		cue.re = regexp.MustCompile(`(?i)\b` + strings.Join(words, `\s+`) + `\b`)
	}

	return c
})

// StatementCueRules returns the statement cues.
func StatementCueRules() StatementCues { return loadStatementCues() }

// Match returns the statement kinds the sentence's cues suggest, sorted, or
// none when it has no cue.
func (c StatementCues) Match(sentence string) []string {
	kinds := map[string]bool{}
	for _, cue := range c.Cues {
		if cue.re.MatchString(sentence) {
			for _, k := range cue.Kinds {
				kinds[k] = true
			}
		}
	}
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
