// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usaspending

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// awardTypeGroups are queried one at a time: the API rejects a request that
// mixes award types from different categories.
var awardTypeGroups = [][]string{
	{"A", "B", "C", "D"},     // contracts
	{"02", "03", "04", "05"}, // grants
	{"06", "10"},             // direct payments
	{"07", "08"},             // loans
}

const (
	awardsPerPage = 100
	awardsMaxPage = 3
)

// award is one row of a spending_by_award result. The field names are the
// display names the API returns for the requested fields.
type award struct {
	AwardID       string  `json:"Award ID"`
	RecipientName string  `json:"Recipient Name"`
	Amount        float64 `json:"Award Amount"`
	Agency        string  `json:"Awarding Agency"`
	StartDate     string  `json:"Start Date"`
	GeneratedID   string  `json:"generated_internal_id"`
}

type awardsPage struct {
	Results      []award `json:"results"`
	PageMetadata struct {
		HasNext bool `json:"hasNext"`
	} `json:"page_metadata"`
}

// parseAwards reads one page of spending_by_award results, returning the rows
// and whether another page follows.
func parseAwards(body []byte) ([]award, bool, error) {
	var p awardsPage
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, false, err
	}
	return p.Results, p.PageMetadata.HasNext, nil
}

// transferID is the stable FundsTransfer ID for an award.
func (a *award) transferID() string {
	if a.GeneratedID != "" {
		return a.GeneratedID
	}
	if a.AwardID != "" {
		return "usaspending:" + a.AwardID
	}
	return ""
}

func (h *awards) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.FundsTransfer), h.plugin.name)
	if err != nil {
		return err
	}

	src := &et.Source{Name: h.name, Confidence: h.plugin.source.Confidence}
	var fundents []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		fundents = org.OrgTransfersReceived(e.Session, e.Entity, since, h.plugin.source)
	} else {
		fundents = h.query(e, e.Entity, o.Name)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	if len(fundents) > 0 {
		h.process(e, fundents)
	}
	return nil
}

func (h *awards) query(e *et.Event, orgent *dbt.Entity, name string) []*dbt.Entity {
	var fundents []*dbt.Entity
	seen := map[string]bool{}

	for _, codes := range awardTypeGroups {
		for page := 1; page <= awardsMaxPage; page++ {
			body, err := h.requestPage(e, name, codes, page)
			if err != nil {
				msg := fmt.Sprintf("failed to obtain awards for %s: %s", name, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				break
			}

			rows, hasNext, err := parseAwards([]byte(body))
			if err != nil {
				msg := fmt.Sprintf("failed to parse awards for %s: %s", name, err)
				e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
				break
			}

			for i := range rows {
				a := &rows[i]
				// Guard against same-name recipients that are not this org.
				if !semantics.SameOrgName(name, a.RecipientName) {
					continue
				}
				id := a.transferID()
				if id == "" || seen[id] {
					continue
				}
				seen[id] = true
				if ent := h.store(e, orgent, a, id); ent != nil {
					fundents = append(fundents, ent)
				}
			}

			if !hasNext {
				break
			}
		}
	}

	return fundents
}

// requestPage posts one page of a spending_by_award query for an award-type
// group and returns the response body.
func (h *awards) requestPage(e *et.Event, name string, codes []string, page int) (string, error) {
	type filters struct {
		RecipientSearchText []string `json:"recipient_search_text"`
		AwardTypeCodes      []string `json:"award_type_codes"`
	}
	req := struct {
		Filters filters  `json:"filters"`
		Fields  []string `json:"fields"`
		Page    int      `json:"page"`
		Limit   int      `json:"limit"`
		Sort    string   `json:"sort"`
		Order   string   `json:"order"`
	}{
		Filters: filters{RecipientSearchText: []string{name}, AwardTypeCodes: codes},
		Fields:  []string{"Award ID", "Recipient Name", "Award Amount", "Awarding Agency", "Start Date"},
		Page:    page,
		Limit:   awardsPerPage,
		Sort:    "Award Amount",
		Order:   "desc",
	}

	bodyJSON, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	_ = support.WaitLimit(e.Session.Ctx(), h.plugin.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    h.plugin.api + "/search/spending_by_award/",
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   string(bodyJSON),
	})
	e.Session.NetSem().Release()
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

func (h *awards) store(e *et.Event, orgent *dbt.Entity, a *award, id string) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	orgacc := org.OrgCheckingAccount(e.Session, orgent, h.plugin.source)
	if orgacc == nil {
		return nil
	}

	f := &oamfin.FundsTransfer{
		ID:              id,
		Amount:          a.Amount,
		Currency:        "USD",
		ReferenceNumber: a.AwardID,
		ExchangeDate:    support.TransferDate(a.StartDate),
	}
	fundent, err := e.Session.DB().CreateAsset(ctx, f)
	if err != nil || fundent == nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer asset for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	if _, err := e.Session.DB().CreateEntityProperty(ctx, fundent, &oamgen.SourceProperty{
		Source:     h.plugin.source.Name,
		Confidence: h.plugin.source.Confidence,
	}); err != nil {
		msg := fmt.Sprintf("failed to create the FundsTransfer source property for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	if err := h.plugin.createRelation(ctx, e.Session, fundent,
		oamgen.SimpleRelation{Name: "recipient"}, orgacc, h.plugin.source.Confidence); err != nil {
		msg := fmt.Sprintf("failed to create the recipient relation for %s: %s", id, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		return nil
	}

	// The awarding agency is the funding party, surfaced by the funding lens.
	if agency, err := org.CreateOrgAsset(e.Session, nil, nil,
		&oamorg.Organization{Name: strings.TrimSpace(a.Agency)}, h.plugin.source); err == nil {
		if err := h.plugin.createRelation(ctx, e.Session, fundent,
			oamgen.SimpleRelation{Name: "third_party"}, agency, h.plugin.source.Confidence); err != nil {
			msg := fmt.Sprintf("failed to create the third_party relation for %s: %s", id, err)
			e.Session.Log().Error(msg, slog.Group("plugin", "name", h.plugin.name, "handler", h.name))
		}
	}

	return fundent
}

func (h *awards) process(e *et.Event, fundents []*dbt.Entity) {
	for _, fund := range fundents {
		f := fund.Asset.(*oamfin.FundsTransfer)
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%f:%s", f.Amount, f.ID),
			Entity:  fund,
			Session: e.Session,
		})
	}
}
