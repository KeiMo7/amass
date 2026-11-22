// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func (s *Scope) AddOrganization(o *oamorg.Organization) bool {
	names := orgNameKeys(o)
	if len(names) == 0 {
		return false
	}

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	var added bool
	for _, name := range names {
		if _, found := s.orgs[name]; !found {
			s.orgs[name] = o
			added = true
		}
	}
	return added
}

func (s *Scope) AddOrgByName(o string) bool {
	return s.AddOrganization(&oamorg.Organization{ID: o, Name: o})
}

func (s *Scope) Organizations() []*oamorg.Organization {
	set := stringset.New()
	defer set.Close()

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	var results []*oamorg.Organization
	for _, v := range s.orgs {
		if o, valid := v.(*oamorg.Organization); valid {
			if !set.Has(o.ID) {
				set.Insert(o.ID)
				results = append(results, o)
			}
		}
	}
	return results
}

// nearMatchAccuracy is the accuracy of a match that is not exact: an
// organization name that is a misspelling of a scope organization's, or a
// street address written differently.
const nearMatchAccuracy = 90

// orgNameKeys returns the name keys (semantics.OrgNameKey) of an
// organization's name and legal name.
func orgNameKeys(o *oamorg.Organization) []string {
	var keys []string
	for _, n := range []string{o.Name, o.LegalName} {
		if k := semantics.OrgNameKey(n); k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// matchesOrg returns the scope organization the organization is: the same
// name once case, punctuation and legal forms are set aside (accuracy 100),
// or a misspelling of it (nearMatchAccuracy, when that is at least conf). A
// name that only contains a scope organization's is not a match.
func (s *Scope) matchesOrg(o *oamorg.Organization, conf int) (oam.Asset, int) {
	names := orgNameKeys(o)
	if len(names) == 0 {
		return nil, 0
	}

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	for _, name := range names {
		if val, found := s.orgs[name]; found {
			return val, 100
		}
	}
	if nearMatchAccuracy < conf {
		return nil, 0
	}
	for n, val := range s.orgs {
		for _, name := range names {
			if _, near := semantics.OrgNameMatch(name, n); near {
				return val, nearMatchAccuracy
			}
		}
	}
	return nil, 0
}
