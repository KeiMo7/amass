// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package adstxt

import (
	"encoding/json"
	"io"
	"strings"
)

// account is one DIRECT line of an ads.txt file.
type account struct {
	system string // the ad system's domain, lower-cased
	id     string // the publisher's account ID on it
}

// key is the account's ads_seller Identifier value.
func (a account) key() string { return a.system + ":" + a.id }

// parseAdsTxt returns the DIRECT accounts an ads.txt file lists, at most max,
// each once. A line is "<ad system domain>, <account id>, <DIRECT|RESELLER>
// [, <certification authority id>]"; a "#" starts a comment, and variable
// lines (contact=, subdomain=, OWNERDOMAIN= and the like) are skipped.
func parseAdsTxt(data string, max int) []account {
	var out []account
	seen := map[string]bool{}
	for _, line := range strings.Split(data, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		system := strings.ToLower(strings.TrimSpace(fields[0]))
		id := strings.TrimSpace(fields[1])
		rel := strings.ToUpper(strings.TrimSpace(fields[2]))
		if rel != "DIRECT" || id == "" || !strings.Contains(system, ".") || strings.ContainsAny(system, " =/") {
			continue
		}
		a := account{system: strings.TrimPrefix(system, "www."), id: id}
		if seen[a.key()] {
			continue
		}
		seen[a.key()] = true
		out = append(out, a)
		if len(out) >= max {
			break
		}
	}
	return out
}

// seller is one entry of a sellers.json file.
type seller struct {
	ID           json.RawMessage `json:"seller_id"` // a string, or a number in some files
	Name         string          `json:"name"`
	Domain       string          `json:"domain"`
	Type         string          `json:"seller_type"`
	Confidential any             `json:"is_confidential"`
}

// id returns the seller ID as text.
func (s seller) id() string { return strings.Trim(strings.TrimSpace(string(s.ID)), `"`) }

// confidential reports whether the ad system withholds the seller's
// identity; the field is 0/1 in the specification but some files use
// booleans.
func (s seller) confidential() bool {
	switch v := s.Confidential.(type) {
	case bool:
		return v
	case float64:
		return v != 0
	}
	return false
}

// parseSellers indexes a sellers.json file's sellers by ID, keeping only
// those whose identity is published.
func parseSellers(r io.Reader) (map[string]seller, error) {
	var f struct {
		Sellers []seller `json:"sellers"`
	}
	if err := json.NewDecoder(r).Decode(&f); err != nil {
		return nil, err
	}

	out := make(map[string]seller, len(f.Sellers))
	for _, s := range f.Sellers {
		if id := s.id(); id != "" && !s.confidential() {
			out[id] = s
		}
	}
	return out, nil
}
