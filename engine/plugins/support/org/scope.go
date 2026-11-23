// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"sync"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// inScopeOrgs remembers the organizations found in a session's scope, by
// session and entity ID. Only positive answers are kept: an organization can
// become associated with the scope as the enumeration learns more.
var inScopeOrgs sync.Map

// InScope reports whether the organization belongs to the enumeration: it is
// in the session's scope, or it is associated with assets in scope (the
// registrant of an in-scope domain, for one), even when the scope may not be
// expanded. A vendor or provider the target merely uses is not. Collectors
// that fan out from an organization (its corporate family, funding, phones,
// other domains) run only for these; identifying an organization (its name,
// LEI, jurisdiction) runs for every organization, so third parties are still
// recognized.
func InScope(sess et.Session, orgent *dbt.Entity) bool {
	if sess == nil || orgent == nil {
		return false
	}
	if _, ok := orgent.Asset.(*oamorg.Organization); !ok {
		return false
	}

	key := sess.ID().String() + ":" + orgent.ID
	if _, found := inScopeOrgs.Load(key); found {
		return true
	}

	in := false
	if _, conf := sess.Scope().IsAssetInScope(orgent.Asset, 0); conf > 0 {
		in = true
	} else if assocs, err := sess.Scope().IsAssociated(&et.Association{Submission: orgent}); err == nil && len(assocs) > 0 {
		in = true
	}
	if in {
		inScopeOrgs.Store(key, true)
	}
	return in
}
