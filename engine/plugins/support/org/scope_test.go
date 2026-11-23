// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestInScope(t *testing.T) {
	sess := plugintest.NewSession(t)
	target := sess.Asset(t, &oamorg.Organization{ID: "ithaca:test", Name: "ithaca college"})
	vendor := sess.Asset(t, &oamorg.Organization{ID: "adobe:test", Name: "adobe"})

	if InScope(sess, target) || InScope(sess, vendor) {
		t.Fatal("an organization was in scope before anything was")
	}

	sess.Scope().Add(target.Asset)
	if !InScope(sess, target) {
		t.Error("the organization in scope is not")
	}
	if InScope(sess, vendor) {
		t.Error("a vendor outside the scope is in it")
	}

	// Only organizations are judged; other assets and nil are not in scope here.
	name := sess.Asset(t, &oamdns.FQDN{Name: "www.ithaca.edu"})
	if InScope(sess, name) || InScope(sess, nil) || InScope(nil, target) {
		t.Error("something other than an organization was in scope")
	}
}
