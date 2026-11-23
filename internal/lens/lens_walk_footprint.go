// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// step is one stored edge seen from the asset being expanded, with its
// semantics.
type step struct {
	edge    graph.Relation
	other   graph.Asset
	forward bool
	attr    string
	purpose string
	vendor  bool
}

func (w *lensWalker) steps(cur graph.Asset) ([]step, error) {
	edges, err := w.neighbors(cur.ID)
	if err != nil {
		return nil, err
	}

	if err := w.prefetch(cur, edges); err != nil {
		return nil, err
	}

	out := make([]step, 0, len(edges))
	for _, e := range edges {
		forward := e.FromID == cur.ID
		otherID := e.ToID
		if !forward {
			otherID = e.FromID
		}
		if otherID == "" || otherID == cur.ID {
			continue
		}

		other, err := w.asset(otherID)
		if err != nil {
			return nil, err
		}

		src, dst := cur.Type, other.Type
		if !forward {
			src, dst = other.Type, cur.Type
		}

		m, ok := w.meaning(src, e.Label, e.Type, dst)
		if !ok {
			continue
		}

		out = append(out, step{edge: e, other: other, forward: forward, attr: m.Attribution, purpose: m.Purpose,
			vendor: m.Vendor})
	}

	return out, nil
}

// controlledFootprint collects the assets controlled by the roots along
// footprintPass. It never enters another Organization except through
// controls (subsidiary, org_unit), and never expands a Person, so a shared
// contact cannot merge two footprints.
func (w *lensWalker) controlledFootprint(roots []graph.Asset) (map[string]graph.Asset, []string, error) {
	owned := map[string]graph.Asset{}
	w.footprint = owned
	var order, queue, deferred []string
	last := followLast()
	admit := func(a graph.Asset, parent string, via graph.Relation) {
		owned[a.ID] = a
		order = append(order, a.ID)
		if w.parent != nil && parent != "" {
			w.parent[a.ID] = parent
			w.via[a.ID] = via
		}
		switch {
		case parent != "" && w.expand != nil && !w.expand[a.Type]:
		case parent != "" && last[a.Type]:
			// follow_last assets count in their turn but are followed only
			// once nothing else is left to follow.
			deferred = append(deferred, a.ID)
		default:
			queue = append(queue, a.ID)
		}
	}
	for _, r := range roots {
		if _, ok := owned[r.ID]; !ok {
			admit(r, "", graph.Relation{})
		}
	}

	// Assets found but not yet admitted wait by type, and the asset limit is
	// shared out a type at a time in turn, so a footprint larger than the
	// limit is a sample of every kind of asset (names, addresses, URLs,
	// services, certificates) rather than the first thousands of subdomains
	// found. Assets of the follow_last types take their turn too, but are
	// followed only when nothing else is left, so they spend few reads.
	type waiting struct {
		asset  graph.Asset
		parent string
		via    graph.Relation
	}
	pending := map[string][]waiting{}
	var kinds []string // types in the order first found, for a stable turn order
	queued := map[string]bool{}
	turn := 0
	next := func() (waiting, bool) {
		for range kinds {
			t := kinds[turn%len(kinds)]
			turn++
			for len(pending[t]) > 0 {
				c := pending[t][0]
				pending[t] = pending[t][1:]
				if _, seen := owned[c.asset.ID]; !seen {
					return c, true
				}
			}
		}

		return waiting{}, false
	}
	// upcoming lists, without taking them, up to n assets next would admit
	// in turn that would then be followed, so their edges can be read with
	// the asset being followed now.
	upcoming := func(n int) []string {
		offset := map[string]int{}
		var out []string
		seen := map[string]bool{}
		t := turn
		for empty := 0; len(out) < n && len(kinds) > 0 && empty < len(kinds); {
			kind := kinds[t%len(kinds)]
			t++
			found := false
			for offset[kind] < len(pending[kind]) {
				c := pending[kind][offset[kind]]
				offset[kind]++
				if _, done := owned[c.asset.ID]; done || seen[c.asset.ID] {
					continue
				}

				seen[c.asset.ID] = true
				found = true
				if c.asset.Type != "Person" && !last[c.asset.Type] && (w.expand == nil || w.expand[c.asset.Type]) {
					out = append(out, c.asset.ID)
				}

				break
			}
			if found {
				empty = 0
			} else {
				empty++
			}
		}

		return out
	}

	for {
		if err := w.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if len(queue) == 0 {
			c, ok := next()
			if !ok {
				if len(deferred) == 0 {
					break
				}

				queue, deferred = deferred, nil
				continue
			}
			if w.skipHostedURLs && c.asset.Type == "URL" && w.footprint[c.parent].Type == "FQDN" {
				w.report.SkippedURLs++
				continue
			}
			if w.summarizeBareAddrs && c.asset.Type == "IPAddress" && w.viaNetblock(c.parent) {
				hosts, err := w.ipHosts(c.asset)
				if err != nil {
					return nil, nil, err
				}
				if !hosts {
					w.report.SummarizedAddresses++
					continue
				}
			}
			if len(owned) >= w.maxAssets {
				w.truncate("controlled asset limit")
				break
			}

			admit(c.asset, c.parent, c.via)
			continue
		}
		if w.report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}

		cur := owned[queue[0]]
		queue = queue[1:]
		if cur.Type == "Person" {
			continue
		}

		// When the asset's edges are not read yet, read them with those of
		// the assets queued or next in turn.
		_, read := w.edges[cur.ID]
		_, ahead := w.prefetched[cur.ID+"\x00out"]
		if !read && !ahead {
			batch := []string{cur.ID}
			for _, id := range queue[:min(len(queue), footprintBatch-1)] {
				if owned[id].Type != "Person" {
					batch = append(batch, id)
				}
			}
			if len(batch) < footprintBatch && len(owned) < w.maxAssets {
				batch = append(batch, upcoming(min(footprintBatch-len(batch), w.maxAssets-len(owned)))...)
			}
			if err := w.prefetchEdges(batch); err != nil {
				return nil, nil, err
			}
		}

		steps, err := w.steps(cur)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range steps {
			if _, seen := owned[s.other.ID]; seen || queued[s.other.ID] || s.other.Type == "Person" ||
				!footprintPass(s) || platformStep(cur, s) ||
				(s.other.Type == "Organization" && (s.attr != graph.AttrControls || w.stopAt[s.other.ID])) {
				continue
			}

			if w.admitOnly != nil && !w.admitOnly[s.other.Type] {
				continue
			}

			queued[s.other.ID] = true
			if _, known := pending[s.other.Type]; !known {
				kinds = append(kinds, s.other.Type)
			}

			pending[s.other.Type] = append(pending[s.other.Type], waiting{asset: s.other, parent: cur.ID, via: s.edge})
		}
	}

	return owned, order, nil
}

// viaNetblock reports whether parentID is a netblock-like record, so an
// IPAddress reached from it is one of its member addresses rather than an
// address a name or service resolves to.
func (w *lensWalker) viaNetblock(parentID string) bool {
	p, ok := w.footprint[parentID]
	if !ok {
		return false
	}

	return p.Type == "Netblock" || p.Type == "IPNetRecord"
}

// ipHosts reports whether addr hosts anything: a name, service, URL or
// certificate on any edge. The summarizing lenses keep such addresses and
// summarize the rest, so a held netblock's empty address space does not crowd
// names and services out of the footprint before the asset limit is reached.
// It matches on the neighbor's type, not footprintPass: the hosting edges
// (FQDN dns_record, port, ptr_record) are infrastructure-attributed and fail
// footprintPass, so gating on it would summarize away the very addresses that
// lead to names. Whether a kept address's neighbors join the footprint is
// still decided by normal expansion.
func (w *lensWalker) ipHosts(addr graph.Asset) (bool, error) {
	steps, err := w.steps(addr)
	if err != nil {
		return false, err
	}

	for _, s := range steps {
		switch s.other.Type {
		case "FQDN", "Service", "URL", "TLSCertificate":
			return true, nil
		}
	}

	return false, nil
}
