// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// LensOwnershipGaps finds assets with no documented owner that share
// signals with the subject's controlled assets, scores them, and names the
// one OAM relationship that would record the subject as their owner. It
// proposes; it never writes.
const LensOwnershipGaps = "ownership_gaps"

// Signal kinds, each defined by the attribution of the bridging edge in the
// semantics table.
const (
	// SignalIdentity: an unowned asset shares an attribute value (phone,
	// address, identifier, URL) with a controlled asset, such as another
	// registrant contact with the same phone number.
	SignalIdentity = "identity"
	// SignalHosting: an unowned asset depends on a controlled asset through
	// an infrastructure edge, such as a name resolving into an owned netblock.
	SignalHosting = "hosting"
	// SignalColisting: an unowned asset is listed beside a controlled asset
	// by a shared asset, such as a certificate naming both.
	SignalColisting = "colisting"
)

// Gap bounds.
const (
	gapMaxCandidates = 200
	gapMaxColisted   = 10
	// gapMaxShared skips an attribute value that more assets carry: a
	// provider's or privacy service's phone or address, not an owner's.
	GapMaxShared = 50
	GapMaxGains  = 10
	// gapMaxGainsCounted bounds the gains counted beyond those named.
	gapMaxGainsCounted = 1000
)

// Gap decisions.
const (
	GapPropose = "propose"
	GapReview  = "review"
	GapWeak    = "weak"
)

// Signal IDs from the signal catalog (semantics/ownership_signals.json).
const (
	sigSharedRegistrant = "shared_registrant_details"
	sigHosting          = "hosting_in_footprint"
	sigColisting        = "certificate_colisting"
	sigSelfHostedDNS    = "self_hosted_dns"
)

// GapSignal is one signal linking a candidate to the subject. Signal is its
// ID in the signal catalog, where its rationale is documented.
type GapSignal struct {
	Signal  string              `json:"signal"`
	Kind    string              `json:"kind"`
	Via     string              `json:"via"`
	Witness []graph.WitnessEdge `json:"witness"`
	// Weight, when set, is this signal's weight, below its catalog weight:
	// a document signal weighs less when it is not first-party or
	// corroborated (DocumentWeight).
	Weight float64 `json:"weight,omitempty"`
}

// ProposedEdge is an OAM relationship that would record the subject as an
// asset's owner.
type ProposedEdge struct {
	FromID       string `json:"from_id"`
	FromType     string `json:"from_type"`
	From         string `json:"from"`
	Label        string `json:"label"`
	RelationType string `json:"relation_type"`
	ToID         string `json:"to_id"`
	ToType       string `json:"to_type"`
	To           string `json:"to"`
}

// String renders the edge as "ContactRecord x --organization--> Organization y".
func (p ProposedEdge) String() string {
	return fmt.Sprintf("%s %s --%s--> %s %s", p.FromType, p.From, p.Label, p.ToType, p.To)
}

// GapCandidate is an unattributed asset with the signals linking it to the
// subject.
type GapCandidate struct {
	AssetID  string      `json:"asset_id"`
	Type     string      `json:"type"`
	Asset    string      `json:"asset"`
	Signals  []GapSignal `json:"signals"`
	Score    float64     `json:"score"`
	Decision string      `json:"decision"`
	// AutoDecision is the decision without document signals: what may be
	// written without review is decided on it (WithoutDocumentSignals).
	AutoDecision string        `json:"auto_decision,omitempty"`
	Attachment   *ProposedEdge `json:"attachment,omitempty"`
	// Alternatives are other relationships that could record the owner; a
	// reviewer chooses, so such a candidate is never proposed outright.
	Alternatives []ProposedEdge `json:"alternatives,omitempty"`
	// Gains are the assets the attachment would bring under the subject.
	Gains []string `json:"gains,omitempty"`
	// GainAssets are the assets behind Gains, in the same order.
	GainAssets []graph.Asset `json:"-"`
}

// OwnershipGapReport is the result of the ownership-gap lens.
type OwnershipGapReport struct {
	Root      graph.Asset `json:"root"`
	Owner     graph.Asset `json:"owner"`
	Footprint int         `json:"footprint"`
	// Domains are the registered domains in the owner's footprint.
	Domains    []string       `json:"domains,omitempty"`
	Candidates []GapCandidate `json:"candidates"`
	Reads      int            `json:"reads"`
	Truncated  bool           `json:"truncated"`
	Reason     string         `json:"reason,omitempty"`
}

// gapSearch holds one ownership-gap run.
type gapSearch struct {
	w       *lensWalker
	owned   map[string]graph.Asset
	owner   graph.Asset
	ownable map[string]bool
	found   map[string]*GapCandidate
	report  *OwnershipGapReport
	// ranges are the address ranges of the owned netblocks: an address in
	// one is owned even when the netblock has more addresses than the lens
	// reads.
	ranges []netip.Prefix
	// domains are the owned registered domains: a name below one is in the
	// subject's namespace even when no stored edge links it.
	domains []string
	// values searches by value for the signals that need it; valueReads
	// counts its searches and tag reads.
	values     ValueSearcher
	valueReads int
	// bountyPrograms are the bug-bounty programs already read.
	bountyPrograms map[string]bool
	// shared caches, by asset ID, whether an address or netblock is shared
	// infrastructure (sharedAddress).
	shared map[string]bool
}

// SearchOwnershipGaps runs the ownership-gap lens from root, an
// Organization or an asset whose documented owner is used.
func SearchOwnershipGaps(ctx context.Context, gr graph.Graph, schema graph.SchemaCatalog, root graph.Asset) (OwnershipGapReport, error) {
	report := OwnershipGapReport{Root: root, Candidates: []GapCandidate{}}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the ownership-gap lens requires relationship semantics")
	}

	bounded, ok := gr.(graph.BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	counters := &ThirdPartyReport{}
	w := newLensWalker(ctx, gr, bounded, meaning, schema.Relations(), root, counters)
	w.parent, w.via = map[string]string{}, map[string]graph.Relation{}
	owner := root
	roots := []graph.Asset{root}
	if root.Type != "Organization" {
		owners, err := w.owningOrganizations(root)
		if err != nil {
			return report, err
		}
		if len(owners) == 0 {
			report.Reason = "no documented owner for " + graph.AssetLabel(root)
			return report, nil
		}

		owner = owners[0]
		roots = append(roots, owner)
	}

	report.Owner = owner
	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}

	report.Footprint = len(owned)
	g := &gapSearch{w: w, owned: owned, owner: owner, found: map[string]*GapCandidate{}, report: &report,
		ownable: map[string]bool{}}
	for _, t := range OwnedTypes(schema) {
		g.ownable[t] = true
	}
	for _, a := range owned {
		switch a.Type {
		case "Netblock":
			if p, err := netip.ParsePrefix(graph.ContentString(a, "cidr")); err == nil {
				g.ranges = append(g.ranges, p.Masked())
			}
		case "DomainRecord":
			if d := strings.ToLower(strings.TrimSuffix(graph.ContentString(a, "domain"), ".")); strings.Contains(d, ".") {
				g.domains = append(g.domains, d)
			}
		}
	}
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if counters.Reads >= lensMaxReads || len(g.found) >= gapMaxCandidates {
			w.truncate("candidate or read limit")
			break
		}
		if err := g.signalsFrom(owned[id]); err != nil {
			return report, err
		}
	}
	if err := g.privateAddressSignals(order); err != nil {
		return report, err
	}
	if err := g.valueSignals(order); err != nil {
		return report, err
	}
	if err := g.documentSignals(); err != nil {
		return report, err
	}
	if err := g.organizationSignals(); err != nil {
		return report, err
	}
	for _, c := range g.found {
		if err := g.finish(c); err != nil {
			return report, err
		}
		if c.Decision != "" {
			report.Candidates = append(report.Candidates, *c)
		}
	}

	rank := map[string]int{GapPropose: 0, GapReview: 1, GapWeak: 2}
	sort.Slice(report.Candidates, func(i, j int) bool {
		a, b := report.Candidates[i], report.Candidates[j]
		if rank[a.Decision] != rank[b.Decision] {
			return rank[a.Decision] < rank[b.Decision]
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}

		return a.Asset < b.Asset
	})
	report.Domains = g.domains
	report.Reads, report.Truncated = counters.Reads, counters.Truncated
	if counters.Reason != "" {
		report.Reason = counters.Reason
	}

	return report, nil
}

// pathTo returns the attribution witness from the subject to an owned asset.
func (g *gapSearch) pathTo(id string) []graph.WitnessEdge {
	return PathWitness(g.w.path(id, g.owned))
}

// add records signal id, found via a route, for candidate a.
func (g *gapSearch) add(a graph.Asset, id, via string, witness []graph.WitnessEdge) {
	if !g.ownable[a.Type] || reverseLookupName(a) {
		return
	}
	if _, mine := g.owned[a.ID]; mine || g.inOwnedRange(a) || g.inOwnedNamespace(a) {
		return
	}

	def, ok := LookupOwnershipSignal(id)
	if !ok {
		return
	}

	c, ok := g.found[a.ID]
	if !ok {
		if len(g.found) >= gapMaxCandidates {
			return
		}

		g.w.assets[a.ID] = a
		c = &GapCandidate{AssetID: a.ID, Type: a.Type, Asset: graph.AssetLabel(a)}
		g.found[a.ID] = c
	}
	for _, s := range c.Signals {
		if s.Signal == id && s.Via == via {
			return
		}
	}

	c.Signals = append(c.Signals, GapSignal{Signal: id, Kind: def.Kind, Via: via, Witness: witness})
}

// inOwnedRange reports whether a is an address inside an owned netblock.
func (g *gapSearch) inOwnedRange(a graph.Asset) bool {
	if a.Type != "IPAddress" {
		return false
	}

	addr, err := netip.ParseAddr(graph.ContentString(a, "address"))
	if err != nil {
		return false
	}
	for _, p := range g.ranges {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// inOwnedNamespace reports whether a is a name, or a URL on a name, at or
// below a registered domain the subject owns.
func (g *gapSearch) inOwnedNamespace(a graph.Asset) bool {
	var host string
	switch a.Type {
	case "FQDN":
		host = graph.AssetLabel(a)
	case "URL":
		if u, err := url.Parse(graph.AssetLabel(a)); err == nil {
			host = u.Hostname()
		}
	default:
		return false
	}
	for _, d := range g.domains {
		if HostWithin(host, d) {
			return true
		}
	}

	return false
}

// reverseLookupName reports whether a is a reverse-DNS lookup name
// (in-addr.arpa, RFC 1035; ip6.arpa, RFC 3596): DNS mechanics for an
// address, not an asset anyone owns.
func reverseLookupName(a graph.Asset) bool {
	if a.Type != "FQDN" {
		return false
	}

	name := strings.ToLower(strings.TrimSuffix(graph.AssetLabel(a), "."))
	return strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa")
}

// finish drops candidates another organization controls, then scores the
// rest and finds their attachment edge and gains.
func (g *gapSearch) finish(c *GapCandidate) error {
	a := g.w.assets[c.AssetID]
	ctl, err := g.w.controllerOf(a, g.owned)
	if err != nil {
		return err
	}
	if ctl.own || len(ctl.orgs) > 0 {
		// Documented as controlled (by the subject or another organization):
		// not a gap. Other controllers are partner signals, not proposals.
		return nil
	}

	edges, gains, err := g.attachment(a, ctl)
	if err != nil {
		return err
	}
	if len(edges) > 0 {
		c.Attachment, c.Alternatives = &edges[0], edges[1:]
	}

	// The answer names the first gains and counts the rest; scope widening
	// uses the named ones.
	more := 0
	if len(gains) > GapMaxGains {
		more, gains = len(gains)-GapMaxGains, gains[:GapMaxGains]
	}

	c.GainAssets = gains
	for _, v := range gains {
		c.Gains = append(c.Gains, v.Type+" "+graph.AssetLabel(v))
	}
	if more > 0 {
		c.Gains = append(c.Gains, fmt.Sprintf("and %d more", more))
	}

	if err := g.contextSignals(a, c); err != nil {
		return err
	}

	// Only one unambiguous relationship can be proposed outright.
	c.Score, c.Decision = ScoreGap(c.Signals, len(edges) == 1)
	_, c.AutoDecision = ScoreGap(WithoutDocumentSignals(c.Signals), len(edges) == 1)
	return nil
}
