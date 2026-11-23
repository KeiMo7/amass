// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// WitnessOf orients a stored edge between a and b as it is stored.
func WitnessOf(e graph.Relation, a, b graph.Asset) graph.WitnessEdge {
	from, to := a, b
	if e.FromID == b.ID {
		from, to = b, a
	}

	return graph.WitnessEdge{EdgeID: e.ID, Label: e.Label, RelationType: e.Type, FromID: from.ID, FromType: from.Type,
		From: graph.AssetLabel(from), ToID: to.ID, ToType: to.Type, To: graph.AssetLabel(to), Detail: RelationDetail(e)}
}

// RelationDetail summarizes the fields a stored relation carries beyond
// its label, such as a port number and protocol ("443/tcp").
func RelationDetail(e graph.Relation) string {
	data, err := json.Marshal(e.Content)
	if err != nil {
		return ""
	}

	var f struct {
		Port     int    `json:"port_number"`
		Protocol string `json:"protocol"`
	}
	if json.Unmarshal(data, &f) != nil {
		return ""
	}
	if f.Port > 0 {
		if f.Protocol != "" {
			return fmt.Sprintf("%d/%s", f.Port, f.Protocol)
		}

		return fmt.Sprint(f.Port)
	}

	return ""
}

// PathWitness returns the edges of a witnessed path.
func PathWitness(p graph.PlanMatch) []graph.WitnessEdge {
	out := make([]graph.WitnessEdge, 0, len(p.Edges))
	for i, e := range p.Edges {
		if i+1 < len(p.Nodes) {
			out = append(out, WitnessOf(e, p.Nodes[i], p.Nodes[i+1]))
		}
	}

	return out
}

// link records how a search reached an asset.
type link struct {
	parent graph.Asset
	edge   graph.Relation
}

// controller is the result of a controller search from one asset.
type controller struct {
	orgs    []graph.Asset
	visited []graph.Asset
	own     bool
	links   map[string]link
}

// witness returns the edges from the search's start to id.
func (c controller) witness(id string, assets map[string]graph.Asset) []graph.WitnessEdge {
	var out []graph.WitnessEdge
	for cur := id; ; {
		l, ok := c.links[cur]
		if !ok {
			break
		}

		out = append([]graph.WitnessEdge{WitnessOf(l.edge, l.parent, assets[cur])}, out...)
		cur = l.parent.ID
	}

	return out
}

// controllerOf searches from a toward the Organization that controls it
// along ownerPass, best first by depth plus the type distance to an
// Organization, so a netblock's registration record is read before its
// thousands of addresses. It stops at the closest Organizations, or when
// it reaches an asset in owned (then own is set).
func (w *lensWalker) controllerOf(a graph.Asset, owned map[string]graph.Asset) (controller, error) {
	return w.controllerSearch(a, owned, lensMaxOwnerPops)
}

// controllerSearch is controllerOf with a pop budget. Ties on depth plus
// distance go to the asset closest to an Organization, so the search
// follows one registration chain to its end before widening.
func (w *lensWalker) controllerSearch(a graph.Asset, owned map[string]graph.Asset, maxPops int) (controller, error) {
	if c, ok := w.controllers[a.ID]; ok {
		return c, nil
	}

	c := controller{links: map[string]link{}}
	type item struct {
		asset graph.Asset
		depth int
	}

	seen := map[string]bool{a.ID: true}
	frontier := []item{{asset: a}}
	best := -1
	for pops := 0; len(frontier) > 0 && pops < maxPops; pops++ {
		if err := w.ctx.Err(); err != nil {
			return c, err
		}

		next, score, dist := 0, -1, -1
		for i, it := range frontier {
			d, ok := w.ownerDist[it.asset.Type]
			if !ok {
				d = len(w.ownerDist)
			}
			if s := it.depth + d; score < 0 || s < score || (s == score && d < dist) {
				next, score, dist = i, s, d
			}
		}
		if best >= 0 && score > best {
			break
		}

		cur := frontier[next]
		frontier = append(frontier[:next], frontier[next+1:]...)
		c.visited = append(c.visited, cur.asset)
		if _, mine := owned[cur.asset.ID]; mine && cur.asset.ID != a.ID {
			c.own = true
			break
		}
		if cur.asset.Type == "Organization" {
			c.orgs = append(c.orgs, cur.asset)
			best = score
			continue
		}

		steps, err := w.steps(cur.asset)
		if err != nil {
			return c, err
		}
		for _, s := range steps {
			if seen[s.other.ID] || s.other.Type == "Person" || !ownerPass(s) || platformStep(cur.asset, s) {
				continue
			}
			if _, ok := w.ownerDist[s.other.Type]; !ok {
				continue
			}

			seen[s.other.ID] = true
			c.links[s.other.ID] = link{parent: cur.asset, edge: s.edge}
			frontier = append(frontier, item{asset: s.other, depth: cur.depth + 1})
		}
	}

	sort.Slice(c.orgs, func(i, j int) bool { return graph.AssetLabel(c.orgs[i]) < graph.AssetLabel(c.orgs[j]) })
	w.controllers[a.ID] = c
	return c, nil
}

// owningOrganizations returns the closest Organizations documented as
// controlling root, so that a domain question also covers its registrant's
// assets. It searches breadth first along ownerPass, a level at a time up
// to lensMaxOwnerDepth, so the nearest owner is found however many
// certificates and URLs share the subject's name.
func (w *lensWalker) owningOrganizations(root graph.Asset) ([]graph.Asset, error) {
	if root.Type == "Organization" {
		return nil, nil
	}

	var orgs []graph.Asset
	seen := map[string]bool{root.ID: true}
	frontier := []graph.Asset{root}
	for depth := 0; depth < lensMaxOwnerDepth && len(frontier) > 0 && len(orgs) == 0; depth++ {
		var next []graph.Asset
		for _, cur := range frontier {
			if err := w.ctx.Err(); err != nil {
				return nil, err
			}

			steps, err := w.steps(cur)
			if err != nil {
				return nil, err
			}
			for _, s := range steps {
				if seen[s.other.ID] || s.other.Type == "Person" || !ownerPass(s) || platformStep(cur, s) {
					continue
				}

				seen[s.other.ID] = true
				if s.other.Type == "Organization" {
					orgs = append(orgs, s.other)
					continue
				}
				if _, ok := w.ownerDist[s.other.Type]; ok {
					next = append(next, s.other)
				}
			}
		}

		frontier = next
	}

	sort.Slice(orgs, func(i, j int) bool { return graph.AssetLabel(orgs[i]) < graph.AssetLabel(orgs[j]) })
	return orgs, nil
}
