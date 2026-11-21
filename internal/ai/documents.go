// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// maxDocumentStatements bounds the statements kept from one document.
const maxDocumentStatements = 30

// maxStatementTerm bounds a statement's subject, object or detail.
const maxStatementTerm = 200

// DocumentStatement is one thing a document states, as the document model
// read it from a stored passage and Go validated it: Quote occurs word for
// word in one of the document's passages, Predicate is in the statement
// catalog (semantics/statement_predicates.json), the types fit the predicate,
// and Subject and Object are both named in that passage.
type DocumentStatement struct {
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Predicate   string `json:"predicate"`
	Object      string `json:"object"`
	ObjectType  string `json:"object_type"`
	Detail      string `json:"detail,omitempty"`
	Quote       string `json:"quote"`
	Model       string `json:"model"`
}

// DocumentReading is what the document model found in one document's
// passages: its category, the statements that passed validation, and why the
// others were rejected.
type DocumentReading struct {
	Category   string              `json:"category,omitempty"`
	Statements []DocumentStatement `json:"statements"`
	Rejected   []string            `json:"rejected,omitempty"`
}

// ReadDocument asks the document model for the statements a document's
// passages make and keeps only those that pass validation. The passages are
// the document's own sentences (doc_passage); the model is the one the user
// named in ai.documents, and nothing it says is trusted until checked here.
func ReadDocument(ctx context.Context, model llm.Model, modelID, url string, passages []string) (DocumentReading, error) {
	var out DocumentReading
	if model == nil {
		return out, errors.New("no document model is configured (ai.documents)")
	}
	if len(passages) == 0 {
		return out, nil
	}

	rules := semantics.StatementPredicateRules()
	history := []llm.Message{
		{Role: "system", Text: documentPrompt(rules)},
		{Role: "user", Text: documentPassages(url, passages)},
	}
	resp, err := generateJSON(ctx, model, history, documentSchema(rules))
	if err != nil {
		return out, err
	}

	var reply struct {
		Category   string              `json:"category"`
		Statements []DocumentStatement `json:"statements"`
	}
	dec := json.NewDecoder(strings.NewReader(llm.ModelJSON(resp.Text)))
	if err := dec.Decode(&reply); err != nil {
		return out, fmt.Errorf("document model reply: %w", err)
	}

	if rules.IsCategory(reply.Category) {
		out.Category = reply.Category
	}
	seen := map[string]bool{}
	for _, s := range reply.Statements {
		if len(out.Statements) >= maxDocumentStatements {
			out.Rejected = append(out.Rejected, "more statements than the limit")
			break
		}
		s.Model = modelID
		if reason := validateStatement(rules, s, passages); reason != "" {
			out.Rejected = append(out.Rejected, reason)
			continue
		}
		key := strings.ToLower(s.Subject + "\x00" + s.Predicate + "\x00" + s.Object)
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Statements = append(out.Statements, s)
	}

	return out, nil
}

// validateStatement returns why a statement is rejected, or "" when it is
// kept.
func validateStatement(rules semantics.StatementPredicates, s DocumentStatement, passages []string) string {
	p, ok := rules.Predicate(s.Predicate)
	if !ok {
		return fmt.Sprintf("unknown predicate %q", s.Predicate)
	}
	if !slices.Contains(p.SubjectTypes, s.SubjectType) || !slices.Contains(p.ObjectTypes, s.ObjectType) {
		return fmt.Sprintf("%s does not take %s and %s", s.Predicate, s.SubjectType, s.ObjectType)
	}

	subject, object := collapse(s.Subject), collapse(s.Object)
	if subject == "" || object == "" || strings.EqualFold(subject, object) ||
		len(subject) > maxStatementTerm || len(object) > maxStatementTerm || len(s.Detail) > maxStatementTerm {
		return fmt.Sprintf("%s: empty, identical or overlong subject or object", s.Predicate)
	}

	quote := collapse(s.Quote)
	if quote == "" {
		return fmt.Sprintf("%s: no quote", s.Predicate)
	}
	for _, passage := range passages {
		text := collapse(passage)
		if !strings.Contains(text, quote) {
			continue
		}
		// both ends must be named in the passage the quote comes from, so a
		// statement cannot introduce a name the document never wrote
		lower := strings.ToLower(text)
		if !strings.Contains(lower, strings.ToLower(subject)) || !strings.Contains(lower, strings.ToLower(object)) {
			return fmt.Sprintf("%s: subject or object not named in the quoted passage", s.Predicate)
		}
		return ""
	}

	return fmt.Sprintf("%s: the quote is not in any passage", s.Predicate)
}

// collapse trims s and joins its whitespace runs into single spaces.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// documentPrompt instructs the document model, listing the predicates and
// categories it may use.
func documentPrompt(rules semantics.StatementPredicates) string {
	var b strings.Builder
	b.WriteString(`You read sentences taken from one published document and report the relationships they state, for an attack-surface inventory.
Rules:
- Report only what a sentence states explicitly. Never infer, guess or use outside knowledge.
- quote must be copied exactly from one sentence, and must contain the words that state the relationship.
- subject and object must be names written in that same sentence, copied as written (not pronouns like "the College" unless that is the name used).
- Use only the predicates below, with the subject and object types they allow. Leave out anything that fits none.
- category is what the whole document appears to be, from the categories below.
Predicates (name: meaning [subject types -> object types]):
`)
	for _, p := range rules.Predicates {
		fmt.Fprintf(&b, "- %s: %s [%s -> %s]", p.Name, p.Description, strings.Join(p.SubjectTypes, "|"),
			strings.Join(p.ObjectTypes, "|"))
		if p.Detail != "" {
			fmt.Fprintf(&b, " detail: %s", p.Detail)
		}
		b.WriteString("\n")
	}
	b.WriteString("Categories:\n")
	for _, c := range rules.Categories {
		fmt.Fprintf(&b, "- %s: %s\n", c.Name, c.Description)
	}
	b.WriteString(`Reply with JSON only: {"category": "...", "statements": [{"subject": "...", "subject_type": "...", "predicate": "...", "object": "...", "object_type": "...", "detail": "...", "quote": "..."}]}. Use an empty statements list when no sentence states one.`)
	return b.String()
}

// documentPassages renders the document's passages for the model, numbered.
func documentPassages(url string, passages []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Document: %s\nSentences:\n", url)
	for i, p := range passages {
		fmt.Fprintf(&b, "%d. %s\n", i+1, p)
	}
	return b.String()
}

// documentSchema constrains the reply to the catalog's predicates, types and
// categories, where the provider supports it.
func documentSchema(rules semantics.StatementPredicates) llm.JSONSchema {
	var names, types, categories []string
	typeSet := map[string]bool{}
	for _, p := range rules.Predicates {
		names = append(names, p.Name)
		for _, t := range append(slices.Clone(p.SubjectTypes), p.ObjectTypes...) {
			typeSet[t] = true
		}
	}
	for t := range typeSet {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, c := range rules.Categories {
		categories = append(categories, c.Name)
	}

	str := map[string]any{"type": "string"}
	return llm.JSONSchema{
		Name:        "document_statements",
		Description: "The category of the document and the relationships its sentences state.",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": map[string]any{"type": "string", "enum": categories},
				"statements": map[string]any{
					"type":     "array",
					"maxItems": maxDocumentStatements,
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"subject":      str,
							"subject_type": map[string]any{"type": "string", "enum": types},
							"predicate":    map[string]any{"type": "string", "enum": names},
							"object":       str,
							"object_type":  map[string]any{"type": "string", "enum": types},
							"detail":       str,
							"quote":        str,
						},
						"required": []string{"subject", "subject_type", "predicate", "object", "object_type", "quote"},
					},
				},
			},
			"required": []string{"category", "statements"},
		},
	}
}

// Stored returns the reading as the statements stored on the document's File:
// the validated statements, and its category as File is_a <category>.
func (r DocumentReading) Stored(url string) []review.StoredStatement {
	var out []review.StoredStatement
	if r.Category != "" {
		out = append(out, review.StoredStatement{Subject: url, SubjectType: "File", Predicate: review.PredicateIsA,
			Object: r.Category})
	}
	for _, s := range r.Statements {
		out = append(out, review.StoredStatement{Subject: s.Subject, SubjectType: s.SubjectType,
			Predicate: s.Predicate, Object: s.Object, ObjectType: s.ObjectType, Detail: s.Detail, Quote: s.Quote,
			Model: s.Model})
	}
	return out
}
