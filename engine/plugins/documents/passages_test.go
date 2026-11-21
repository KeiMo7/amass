// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package documents

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func TestSplitSentences(t *testing.T) {
	got := splitSentences("The College is   here. The Foundation\nis a division of it!\n\nNext block? Yes")
	want := []string{"The College is here.", "The Foundation is a division of it!", "Next block?", "Yes"}
	if !slices.Equal(got, want) {
		t.Errorf("sentences %q", got)
	}
}

// A sentence is kept when it names something the document links and states a
// relationship, or names two such things; others are not.
func TestSelectPassages(t *testing.T) {
	text := "Welcome to campus. The Herkimer College Foundation is a division of the College. " +
		"Email helpdesk@herkimer.edu or visit portal.herkimer.edu for help. " +
		"Herkimer has a new library. The weather is a division of nothing we know."
	got := selectPassages(semantics.StatementCueRules(), text,
		[]string{"herkimer", "helpdesk@herkimer.edu", "portal.herkimer.edu", "it"})
	want := []string{
		"The Herkimer College Foundation is a division of the College.",
		"Email helpdesk@herkimer.edu or visit portal.herkimer.edu for help.",
	}
	if !slices.Equal(got, want) {
		t.Errorf("passages %q", got)
	}
}

// Passages are bounded in number and length, and repeats are kept once.
func TestSelectPassagesBounds(t *testing.T) {
	rules := semantics.StatementCueRules()
	var b strings.Builder
	for i := 0; i < rules.MaxPassages+5; i++ {
		b.WriteString("Acme Widgets is a subsidiary of Acme Holdings number ")
		b.WriteString(strings.Repeat("x", i+1))
		b.WriteString(". ")
	}
	b.WriteString("Acme Widgets is a subsidiary of Acme Holdings number x. ")
	got := selectPassages(rules, b.String(), []string{"acme widgets"})
	if len(got) != rules.MaxPassages {
		t.Errorf("%d passages, want %d", len(got), rules.MaxPassages)
	}

	long := strings.Repeat("word ", 300) + "Acme Widgets is a subsidiary of Acme Holdings " + strings.Repeat("more ", 300)
	got = selectPassages(rules, long, []string{"acme widgets"})
	if len(got) != 1 || len(got[0]) > rules.MaxPassageChars || !strings.Contains(got[0], "Acme Widgets is a subsidiary") {
		t.Errorf("long passage %q", got)
	}
	if !strings.Contains(long, got[0]) {
		t.Error("a passage is not verbatim text of the document")
	}
}

func TestPublisherName(t *testing.T) {
	for host, want := range map[string]string{"www.herkimer.edu": "herkimer", "a.b.example.co.uk": "example", "localhost": ""} {
		if got := publisherName(host); got != want {
			t.Errorf("publisherName(%q) = %q, want %q", host, got, want)
		}
	}
}

// The collector stores the passages of a document as doc_passage properties.
func TestPassageLeads(t *testing.T) {
	pdf := "%PDF-1.4\n1 0 obj\n<< /Author (Jane Q. Doe) /Producer (Acme PDF 2.1) >>\nendobj\n" +
		"2 0 obj\n<< /Length 160 >>\nstream\n" +
		"BT (The Example Foundation is a division of Example University. The cafeteria opens at noon.) Tj ET" +
		"\nendstream\nendobj\ntrailer\n<< /Info 1 0 R >>\n%%EOF\n"
	f := newFixture(t, http.StatusOK, pdf)
	raw := "https://www.example.com/about/foundation.pdf"
	if err := f.d.check(f.event(t, raw)); err != nil {
		t.Fatal(err)
	}
	fent := f.file(t, raw)
	if fent == nil {
		t.Fatal("no File stored")
	}
	if got := props(t, f, fent)[PropPassage]; got != "The Example Foundation is a division of Example University." {
		t.Errorf("passage %q", got)
	}
}
