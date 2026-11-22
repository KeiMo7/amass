// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Advertising seller accounts (engine plugin adstxt): a domain's ads.txt URL
// carries a fingerprint Identifier (ads_seller, "<ad system>:<account>") for
// each DIRECT account it lists, with the ad system's sellers.json details as
// properties on the Identifier.
const (
	adsPropSellerType   = "seller_type"
	adsPropSellerDomain = "seller_domain"
	adsIntermediary     = "INTERMEDIARY"
)

// adsSellerPivot finds the other registered domains tied to the
// organization's own advertising seller accounts: a domain whose ads.txt
// lists the same DIRECT account (strong, as a shared analytics property is,
// within the same shared-value cap), and the domain the ad system's
// sellers.json gives for the account when it is another domain (supporting).
// An account the ad system lists as an INTERMEDIARY belongs to a sales house,
// not the publisher, and gives neither.
func adsSellerPivot(ctx context.Context, g graph.Graph, ownApexes, ownDomains []string,
	add func(string, string, string, ...graph.WitnessEdge) bool) {
	resolver, ok := g.(graph.AssetResolver)
	if !ok {
		return
	}

	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		apex, err := g.GetAsset(ctx, apexID)
		if err != nil || graph.FQDNName(apex) == "" {
			continue
		}
		for _, path := range semantics.AdsTxtCatalog().Files {
			res, err := resolver.ResolveAsset(ctx, graph.AssetSelector{Type: "URL", Field: "url",
				Value: "https://" + graph.FQDNName(apex) + path}, 2)
			if err != nil || len(res.Candidates) == 0 {
				continue
			}
			file := res.Candidates[0].Asset
			if !adsAccounts(ctx, g, file, ownDomains, seen, add) {
				return
			}
		}
	}
}

// adsAccounts adds the domains tied to the DIRECT accounts one ads.txt file
// lists. It returns false when add is full.
func adsAccounts(ctx context.Context, g graph.Graph, file graph.Asset, ownDomains []string, seen map[string]bool,
	add func(string, string, string, ...graph.WitnessEdge) bool) bool {
	fps, err := g.Edges(ctx, file.ID, "out", "fingerprint", time.Time{})
	if err != nil {
		return true
	}
	for _, fe := range fps {
		ident, err := g.GetAsset(ctx, fe.ToID)
		if err != nil || graph.ContentString(ident, "id_type") != fingerprint.AdsSeller || seen[ident.ID] {
			continue
		}
		seen[ident.ID] = true
		value := graph.ContentString(ident, "id")

		var sellerType, sellerDomain string
		if ev, err := g.Evidence(ctx, ident.ID, 20); err == nil {
			if v := propertyValues(ev, adsPropSellerType); len(v) > 0 {
				sellerType = strings.ToUpper(v[0])
			}
			if v := propertyValues(ev, adsPropSellerDomain); len(v) > 0 {
				sellerDomain = v[0]
			}
		}
		if sellerType == adsIntermediary {
			continue
		}

		ownW := graph.WitnessEdge{EdgeID: fe.ID, Label: "fingerprint", RelationType: fe.Type, FromID: file.ID,
			FromType: "URL", ToID: ident.ID, ToType: "Identifier", To: fingerprint.AdsSeller + ":" + value}
		if !fingerprintSiblings(ctx, g, file.ID, ident.ID, SigSharedAdsSeller,
			"same DIRECT ad seller account "+value, ownW, add) {
			return false
		}

		system, _, _ := strings.Cut(value, ":")
		host := webHost(sellerDomain)
		dom := graph.RegisteredDomain(host)
		if dom == "" || withinAny(host, ownDomains) || dom == graph.RegisteredDomain(system) {
			continue
		}
		if !add(dom, SigAdsSellerDomain, "the domain "+system+" lists for ad seller account "+value, ownW) {
			return false
		}
	}
	return true
}
