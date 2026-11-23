// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// isMailProvider reports whether host is a mail exchanger of a known mail
// provider (email.json mail_providers), so the shared-mail-exchanger horizontal
// signal can skip it regardless of how many of the provider's customers are in
// the database.
func isMailProvider(host string) bool {
	return mailProviderOf(loadEmailRules(), host) != ""
}

// policyReferencePivot adds related domains that point their published mail
// policy at one of the organization's own apex domains: another domain whose SPF
// record authorizes the org's domain to send (spf_authorizes) or whose DMARC
// record sends its reports to the org's domain (dmarc_reports_to). The engine
// derives both edges from the publishing domain's TXT records and runs them from
// the publishing apex to the referenced domain, so this walks the incoming edges
// of the given label on each of the organization's own apexes. A referenced
// domain pointed at by more than maxPublishers distinct apexes, or one a known
// mail-policy provider operates (isProvider), is shared mail-policy
// infrastructure and is skipped, not scored.
//
// For SPF, exclusive (the organization's domains) sets the strong tier: a
// publisher that sends all its mail through the organization (every name and
// range its SPF record authorizes is inside exclusive), when at most
// spfExclusiveMaxPublishers domains reference the organization's domain.
func policyReferencePivot(ctx context.Context, g graph.Graph, ownApexes []string, label,
	signalID, signalLabel string, maxPublishers int, isProvider func(string) bool, exclusive []string,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	for _, apexID := range ownApexes {
		target, err := g.GetAsset(ctx, apexID)
		if err != nil {
			continue
		}
		if isProvider(graph.RegisteredDomain(graph.FQDNName(target))) {
			continue // the organization's own domain is itself a shared endpoint
		}

		edges, err := g.Edges(ctx, apexID, "in", label, time.Time{})
		if err != nil {
			continue
		}
		apexSet := map[string]bool{}
		type publisher struct {
			apex string
			edge graph.Relation
		}
		var pubs []publisher
		for _, pe := range edges {
			pf, err := g.GetAsset(ctx, pe.FromID)
			if err != nil {
				continue
			}
			apex := graph.RegisteredDomain(graph.FQDNName(pf))
			if apex == "" {
				continue
			}
			apexSet[apex] = true
			pubs = append(pubs, publisher{apex: apex, edge: pe})
		}
		if len(apexSet) > maxPublishers {
			continue // a shared mail-policy endpoint referenced by many domains
		}

		for _, p := range pubs {
			w := graph.WitnessEdge{EdgeID: p.edge.ID, Label: label, RelationType: p.edge.Type,
				FromID: p.edge.FromID, FromType: "FQDN", ToID: p.edge.ToID, ToType: "FQDN"}
			sig, sigLabel := signalID, signalLabel
			if len(exclusive) > 0 && len(apexSet) <= spfExclusiveMaxPublishers &&
				sendsOnlyThrough(ctx, g, p.edge.FromID, exclusive) {
				sig, sigLabel = SigSPFExclusive, "sends all its mail through the organization (SPF)"
			}
			if !add(p.apex, sig, sigLabel, w) {
				return
			}
		}
	}
}

// spfExclusiveMaxPublishers is the most domains that may reference one of the
// organization's domains in SPF for one of them to count as sending only
// through it: an email or IT provider is referenced by many.
const spfExclusiveMaxPublishers = 5

// sendsOnlyThrough reports whether every name and address range a domain's
// SPF record authorizes is inside the given domains.
func sendsOnlyThrough(ctx context.Context, g graph.Graph, apexID string, domains []string) bool {
	edges, err := g.Edges(ctx, apexID, "out", "spf_authorizes", time.Time{})
	if err != nil || len(edges) == 0 {
		return false
	}
	for _, e := range edges {
		a, err := g.GetAsset(ctx, e.ToID)
		if err != nil || a.Type != "FQDN" || !withinAny(graph.FQDNName(a), domains) {
			return false
		}
	}
	return true
}

// withinAny reports whether host is one of domains or a name below one.
func withinAny(host string, domains []string) bool {
	for _, d := range domains {
		if HostWithin(host, d) {
			return true
		}
	}
	return false
}

// ownHostTier is the strong tier of a shared-host signal: a host inside the
// organization's own domains.
type ownHostTier struct {
	signalID, label string
	domains         []string
}

// sharedDNSHostPivot adds related domains that share a DNS host record of the
// given RR type — a name server (NS) or a mail exchanger (MX) — with one of the
// organization's own apex domains. In OAM both are the same shape (an apex FQDN
// pointing to a server FQDN via a dns_record edge), so both are found the same
// way, differing only by RR type. A host a known provider operates (isProvider,
// from a curated provider list) is skipped regardless of database coverage; a
// host shared by more than maxApexes distinct apexes is treated as provider
// infrastructure the list does not yet name and is skipped too. Neither is
// scored. add returning false (the domain cap) stops the pivot.
func sharedDNSHostPivot(ctx context.Context, g graph.Graph, ownApexes []string, rrType int,
	signalID, signalLabel string, maxApexes int, isProvider func(string) bool, own ownHostTier,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	seenHost := map[string]bool{}
	for _, apexID := range ownApexes {
		hosts, err := g.Edges(ctx, apexID, "out", "dns_record", time.Time{})
		if err != nil {
			continue
		}
		for _, he := range hosts {
			if relationRRType(he) != rrType || seenHost[he.ToID] {
				continue
			}
			seenHost[he.ToID] = true

			// A name server or mail exchanger a known provider operates serves
			// many unrelated customers, so it is never ownership evidence, even
			// when few of its tenants are in the database yet.
			host, err := g.GetAsset(ctx, he.ToID)
			if err == nil && isProvider(graph.FQDNName(host)) {
				continue
			}
			sig, sigLabel := signalID, signalLabel
			if err == nil && withinAny(graph.FQDNName(host), own.domains) {
				sig, sigLabel = own.signalID, own.label+": "+graph.FQDNName(host)
			}

			others, err := g.Edges(ctx, he.ToID, "in", "dns_record", time.Time{})
			if err != nil {
				continue
			}
			apexSet := map[string]bool{}
			type dnsSibling struct {
				apex string
				edge graph.Relation
			}
			var sibs []dnsSibling
			for _, oe := range others {
				if relationRRType(oe) != rrType {
					continue
				}
				of, err := g.GetAsset(ctx, oe.FromID)
				if err != nil {
					continue
				}
				apex := graph.RegisteredDomain(graph.FQDNName(of))
				if apex == "" {
					continue
				}
				apexSet[apex] = true
				sibs = append(sibs, dnsSibling{apex: apex, edge: oe})
			}
			if len(apexSet) > maxApexes {
				continue // a shared or provider host
			}

			hostW := graph.WitnessEdge{EdgeID: he.ID, Label: "dns_record", RelationType: he.Type,
				FromID: he.FromID, FromType: "FQDN", ToID: he.ToID, ToType: "FQDN"}
			for _, s := range sibs {
				sibW := graph.WitnessEdge{EdgeID: s.edge.ID, Label: "dns_record", RelationType: s.edge.Type,
					FromID: s.edge.FromID, FromType: "FQDN", ToID: s.edge.ToID, ToType: "FQDN"}
				if !add(s.apex, sig, sigLabel, hostW, sibW) {
					return
				}
			}
		}
	}
}

// delegationMaxListings bounds the registrations read for one name server of a
// delegation set.
const delegationMaxListings = 5000

// delegationSetPivot finds the registrations listing exactly the same full set
// of name servers as one of the organization's own registrations, when the set
// belongs to a provider that gives each account or zone its own set
// (dns.json assignment unique_set), and adds their apexes.
func delegationSetPivot(ctx context.Context, g graph.Graph, ownDRs []string,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	seen := map[string]bool{}
	for _, drID := range ownDRs {
		if seen[drID] {
			continue
		}
		seen[drID] = true

		nsEdges, err := g.Edges(ctx, drID, "out", "name_server", time.Time{})
		if err != nil || len(nsEdges) < 4 {
			continue
		}
		hosts := make([]string, 0, len(nsEdges))
		for _, e := range nsEdges {
			ns, err := g.GetAsset(ctx, e.ToID)
			if err != nil {
				hosts = nil
				break
			}
			hosts = append(hosts, graph.FQDNName(ns))
		}
		if p, ok := nameServerSetProvider(hosts); !ok || p.Assignment != AssignmentUniqueSet {
			continue
		}

		// the registrations listing every server of the set, besides this one
		var shared map[string]graph.Relation
		for _, nse := range nsEdges {
			others, err := g.Edges(ctx, nse.ToID, "in", "name_server", time.Time{})
			if err != nil || len(others) > delegationMaxListings {
				shared = nil
				break
			}
			listing := map[string]graph.Relation{}
			for _, oe := range others {
				if oe.FromID != drID {
					listing[oe.FromID] = oe
				}
			}
			if shared == nil {
				shared = listing
				continue
			}
			for id := range shared {
				if _, ok := listing[id]; !ok {
					delete(shared, id)
				}
			}
		}

		apexes := map[string]graph.Relation{}
		for id, e := range shared {
			odr, err := g.GetAsset(ctx, id)
			if err != nil {
				continue
			}
			if apex := strings.ToLower(strings.TrimSpace(graph.ContentString(odr, "domain"))); apex != "" {
				apexes[apex] = e
			}
		}
		if len(apexes) == 0 || len(apexes) > nsMaxApexes {
			continue
		}

		ownW := graph.WitnessEdge{EdgeID: nsEdges[0].ID, Label: "name_server", RelationType: nsEdges[0].Type,
			FromID: nsEdges[0].FromID, FromType: "DomainRecord", ToID: nsEdges[0].ToID, ToType: "FQDN"}
		for _, apex := range sortedRelationKeys(apexes) {
			e := apexes[apex]
			sibW := graph.WitnessEdge{EdgeID: e.ID, Label: "name_server", RelationType: e.Type,
				FromID: e.FromID, FromType: "DomainRecord", ToID: e.ToID, ToType: "FQDN"}
			if !add(apex, SigDNSDelegationSet, "same DNS provider delegation set", ownW, sibW) {
				return
			}
		}
	}
}
