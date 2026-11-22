// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
)

// LinkAsset creates asset with src as its source and links it from from with
// a simple relation labeled label. It returns the asset's entity, or nil when
// it was not created.
func LinkAsset(ctx context.Context, sess et.Session, from *dbt.Entity, label string, asset oam.Asset,
	src *et.Source) *dbt.Entity {
	if from == nil || asset == nil {
		return nil
	}
	ent, err := sess.DB().CreateAsset(ctx, asset)
	if err != nil || ent == nil {
		return nil
	}
	AddSource(ctx, sess, ent, src)
	Link(ctx, sess, from, label, ent, src)
	return ent
}

// LinkContactRecord creates the ContactRecord discovered at key (the URL or
// other locator of the published contact information) and links it from
// owner with a simple relation labeled label, such as contact.
func LinkContactRecord(ctx context.Context, sess et.Session, owner *dbt.Entity, label, key string,
	src *et.Source) *dbt.Entity {
	if key == "" {
		return nil
	}
	return LinkAsset(ctx, sess, owner, label, &contact.ContactRecord{DiscoveredAt: key}, src)
}

// EmailIdentifier returns the email Identifier for an address.
func EmailIdentifier(email string) *general.Identifier {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil
	}
	return &general.Identifier{UniqueID: general.EmailAddress + ":" + email, ID: email,
		Type: general.EmailAddress}
}

// LinkContactValue links one published contact value to a ContactRecord: an
// email address (mailto: or bare) as an email Identifier (id), an http(s)
// URL (url), or a phone number (tel: or bare) as a Phone (phone). It
// returns the value's entity, or nil when the value is none of these.
func LinkContactValue(ctx context.Context, sess et.Session, cr *dbt.Entity, value string,
	src *et.Source) *dbt.Entity {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "mailto:"):
		return LinkEmail(ctx, sess, cr, "id", value[len("mailto:"):], src)
	case strings.HasPrefix(lower, "tel:"):
		return linkPhone(ctx, sess, cr, value[len("tel:"):], src)
	case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
		if u := RawURLToOAM(value); u != nil {
			return LinkAsset(ctx, sess, cr, "url", u, src)
		}
		return nil
	case strings.Contains(value, "@") && !strings.Contains(value, "://"):
		return LinkEmail(ctx, sess, cr, "id", value, src)
	}
	return linkPhone(ctx, sess, cr, value, src)
}

// LinkEmail creates the email Identifier for an address and links it from
// from with a simple relation labeled label.
func LinkEmail(ctx context.Context, sess et.Session, from *dbt.Entity, label, email string,
	src *et.Source) *dbt.Entity {
	id := EmailIdentifier(email)
	if id == nil {
		return nil
	}
	return LinkAsset(ctx, sess, from, label, id, src)
}

func linkPhone(ctx context.Context, sess et.Session, cr *dbt.Entity, value string, src *et.Source) *dbt.Entity {
	phone := PhoneToOAMPhone(strings.TrimSpace(value), "", "")
	if phone == nil {
		return nil
	}
	if phone.Type == "" {
		phone.Type = contact.PhoneTypeRegular
	}
	return LinkAsset(ctx, sess, cr, "phone", phone, src)
}
