// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// grant is one award normalized across the three APIs before it is stored.
type grant struct {
	id, date, agency, recipient string
	amount                      float64
}

func (h *source) get(e *et.Event, u string) (string, error) {
	return h.request(e, &amasshttp.Request{URL: u})
}

func (h *source) postJSON(e *et.Event, u, body string) (string, error) {
	return h.request(e, &amasshttp.Request{
		URL:    u,
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   body,
	})
}

func (h *source) request(e *et.Event, r *amasshttp.Request) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, r)
	e.Session.NetSem().Release()
	cancel()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	if resp.Body == "" {
		return "", errors.New("empty body")
	}
	return resp.Body, nil
}

// store writes a matched grant as a FundsTransfer received by the organization,
// with the funding agency as the third_party funder.
func (h *source) store(e *et.Event, orgent *dbt.Entity, g *grant) *dbt.Entity {
	if g.id == "" {
		return nil
	}
	// The Asset Database rejects a FundsTransfer with a non-positive amount,
	// so skip a grant we could find no amount for rather than logging a
	// storage error for every one.
	if g.amount <= 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := org.OrgCheckingAccount(e.Session, orgent, h.src)
	if orgacc == nil {
		return nil
	}

	fundent, err := e.Session.DB().CreateAsset(ctx, &oamfin.FundsTransfer{
		ID:              g.id,
		Amount:          g.amount,
		Currency:        "USD",
		ReferenceNumber: g.id,
		ExchangeDate:    support.TransferDate(g.date),
	})
	if err != nil || fundent == nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer for %s: %s", g.id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.name))
		return nil
	}
	support.AddSource(ctx, e.Session, fundent, h.src)
	if _, err := support.Relate(ctx, e.Session, fundent,
		&general.SimpleRelation{Name: "recipient"}, orgacc, h.src); err != nil {
		return nil
	}
	if agency, err := org.CreateOrgAsset(e.Session, nil, nil,
		&oamorg.Organization{Name: strings.TrimSpace(g.agency)}, h.src); err == nil {
		_, _ = support.Relate(ctx, e.Session, fundent,
			&general.SimpleRelation{Name: "third_party"}, agency, h.src)
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name: fmt.Sprintf("%f:%s", g.amount, g.id), Entity: fundent, Session: e.Session,
	})
	return fundent
}
