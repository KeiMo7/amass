// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// A domain whose ads.txt lists the organization's DIRECT account is strong
// evidence, the seller domain sellers.json gives is supporting, and an
// intermediary's account gives nothing.
func TestAdsSellerPivot(t *testing.T) {
	g := graphtest.PlannedGraph{FakeGraph: graphtest.FakeGraph{Assets: map[string]graph.Asset{},
		EvidenceByID: map[string][]graph.Evidence{}}}
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	adsFile := func(id, host string) {
		raw := "https://" + host + "/ads.txt"
		add(id, "URL", raw, map[string]any{"url": raw, "host": host, "path": "/ads.txt"})
		add(host, "FQDN", host, map[string]any{"name": host})
		link(id, "domain", host)
	}
	ident := func(id, value string) {
		add(id, "Identifier", "ads_seller:"+value, map[string]any{"unique_id": "ads_seller:" + value, "id": value,
			"id_type": "ads_seller"})
	}

	adsFile("own", "acme.com")
	adsFile("sib", "acme-games.net")
	adsFile("other", "unrelated.org")
	ident("pub", "google.com:pub-1")
	ident("house", "rubiconproject.com:5678")
	link("own", "fingerprint", "pub")
	link("sib", "fingerprint", "pub")
	link("own", "fingerprint", "house")
	link("other", "fingerprint", "house")
	g.EvidenceByID["pub"] = []graph.Evidence{graphtest.SimpleProp(adsPropSellerType, "PUBLISHER"),
		graphtest.SimpleProp(adsPropSellerDomain, "acme-corp.com")}
	g.EvidenceByID["house"] = []graph.Evidence{graphtest.SimpleProp(adsPropSellerType, "INTERMEDIARY")}

	got := map[string]string{}
	adsSellerPivot(context.Background(), g, []string{"acme.com"}, []string{"acme.com"},
		func(apex, sig, _ string, _ ...graph.WitnessEdge) bool {
			got[apex] = sig
			return true
		})

	want := map[string]string{"acme-games.net": SigSharedAdsSeller, "acme-corp.com": SigAdsSellerDomain}
	if len(got) != len(want) {
		t.Fatalf("pivot = %v, want %v", got, want)
	}
	for apex, sig := range want {
		if got[apex] != sig {
			t.Errorf("%s: %q, want %q", apex, got[apex], sig)
		}
	}
}
