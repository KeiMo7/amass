// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// PropDocStatement is the File property holding one statement the document
// model read from the File's passages, as a JSON StoredStatement.
const PropDocStatement = "doc_statement"

// PredicateIsA is the predicate of the statement recording a document's
// category: File is_a <category>.
const PredicateIsA = "is_a"

// Document statement record statuses.
const (
	StatementsStored = "stored"
	StatementsUndone = "undone"
)

// StoredStatement is the value of a doc_statement property. It is an
// observation of what a document says (principle 10), never a conclusion:
// Quote is the passage text it was read from, Model the document model that
// read it, and Source is always amass-ai.
type StoredStatement struct {
	Subject     string `json:"subject"`
	SubjectType string `json:"subject_type"`
	Predicate   string `json:"predicate"`
	Object      string `json:"object"`
	ObjectType  string `json:"object_type,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Quote       string `json:"quote,omitempty"`
	Model       string `json:"model"`
	Source      string `json:"source"`
}

// DocumentStatementStore writes and removes doc_statement properties.
type DocumentStatementStore interface {
	FindEntityById(ctx context.Context, id string) (*dbt.Entity, error)
	CreateEntityProperty(ctx context.Context, e *dbt.Entity, p oam.Property) (*dbt.EntityTag, error)
	DeleteEntityTag(ctx context.Context, id string) error
}

// DocumentStatementRecord journals one stored reading of a document so it can
// be undone. It holds no document text, only counts and the property tags,
// since the journal is readable where the passages may be withheld.
type DocumentStatementRecord struct {
	ID         string         `json:"id"`
	FileID     string         `json:"file_id"`
	URL        string         `json:"url"`
	Model      string         `json:"model"`
	Predicates map[string]int `json:"predicates"`
	TagIDs     []string       `json:"tag_ids"`
	Status     string         `json:"status"`
	Actor      string         `json:"actor,omitempty"`
	At         time.Time      `json:"at"`
}

// documentStatementUndo journals that a stored reading was undone.
type documentStatementUndo struct {
	ID    string    `json:"id"`
	Actor string    `json:"actor"`
	At    time.Time `json:"at"`
}

// StoreDocumentStatements writes each statement as a doc_statement property
// of the File, tagged amass-ai, and journals the property tags so the reading
// can be undone (principle 9). When the journal cannot be written, the
// properties just written are removed again and the error returned: nothing is
// stored that cannot be undone.
func StoreDocumentStatements(ctx context.Context, w DocumentStatementStore, j *Journal, fileID, url, model string,
	statements []StoredStatement) (DocumentStatementRecord, error) {
	rec := DocumentStatementRecord{FileID: fileID, URL: url, Model: model, Predicates: map[string]int{},
		Status: StatementsStored, Actor: InferenceSource, At: time.Now().UTC()}
	if fileID == "" || model == "" {
		return rec, errors.New("document statements need a File and a model")
	}
	if len(statements) == 0 {
		return rec, nil
	}

	file, err := w.FindEntityById(ctx, fileID)
	if err != nil || file == nil {
		return rec, fmt.Errorf("file %s not found: %w", fileID, err)
	}
	if file.Asset == nil || file.Asset.AssetType() != oam.File {
		return rec, fmt.Errorf("entity %s is not a File", fileID)
	}

	rollback := func() {
		for _, id := range rec.TagIDs {
			_ = w.DeleteEntityTag(ctx, id)
		}
	}
	for _, s := range statements {
		s.Model, s.Source = model, InferenceSource
		value, err := json.Marshal(s)
		if err != nil {
			rollback()
			return rec, err
		}

		tag, err := w.CreateEntityProperty(ctx, file, &oamgen.SimpleProperty{
			PropertyName: PropDocStatement, PropertyValue: string(value)})
		if err != nil || tag == nil {
			rollback()
			return rec, fmt.Errorf("store statement on %s: %w", url, err)
		}
		rec.TagIDs = append(rec.TagIDs, tag.ID)
		rec.Predicates[s.Predicate]++
	}

	rec.ID = documentRecordID(fileID, rec.At)
	if err := j.append("doc_statements", rec); err != nil {
		rollback()
		return rec, fmt.Errorf("journal document statements: %w", err)
	}
	return rec, nil
}

func documentRecordID(fileID string, at time.Time) string {
	return "doc:" + fileID + ":" + at.Format("20060102T150405.000000000Z")
}

// DocumentStatementRecords returns the journaled readings with the latest
// status of each, oldest first.
func (j *Journal) DocumentStatementRecords() ([]DocumentStatementRecord, error) {
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	byID := map[string]*DocumentStatementRecord{}
	var order []string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil {
			continue
		}
		switch head.Kind {
		case "doc_statements":
			var r DocumentStatementRecord
			if json.Unmarshal(head.Data, &r) == nil && r.ID != "" {
				if _, ok := byID[r.ID]; !ok {
					order = append(order, r.ID)
				}
				byID[r.ID] = &r
			}
		case "doc_statements_undone":
			var u documentStatementUndo
			if json.Unmarshal(head.Data, &u) == nil {
				if r, ok := byID[u.ID]; ok {
					r.Status, r.Actor, r.At = StatementsUndone, u.Actor, u.At
				}
			}
		}
	}

	out := make([]DocumentStatementRecord, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].At.Before(out[b].At) })
	return out, nil
}

// StoredDocumentReadings returns the IDs of the readings of a File that are
// stored and not undone.
func (j *Journal) StoredDocumentReadings(fileID string) ([]string, error) {
	recs, err := j.DocumentStatementRecords()
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, r := range recs {
		if r.FileID == fileID && r.Status == StatementsStored {
			ids = append(ids, r.ID)
		}
	}
	return ids, nil
}

// UndoDocumentStatements removes the doc_statement properties a stored reading
// wrote and journals the undo. A property that is already gone is not an
// error; any other failure stops before the undo is journaled, so it can be
// retried.
func UndoDocumentStatements(ctx context.Context, w DocumentStatementStore, j *Journal, id, actor string) error {
	if strings.TrimSpace(actor) == "" {
		return errors.New("actor required")
	}

	recs, err := j.DocumentStatementRecords()
	if err != nil {
		return err
	}

	var rec *DocumentStatementRecord
	for i := range recs {
		if recs[i].ID == id {
			rec = &recs[i]
		}
	}
	if rec == nil {
		return fmt.Errorf("no document reading %s", id)
	}
	if rec.Status != StatementsStored {
		return fmt.Errorf("document reading %s is already %s", id, rec.Status)
	}

	for _, tag := range rec.TagIDs {
		if err := w.DeleteEntityTag(ctx, tag); err != nil && !isNotFound(err) {
			return fmt.Errorf("remove statement %s: %w", tag, err)
		}
	}
	return j.append("doc_statements_undone", documentStatementUndo{ID: id, Actor: actor, At: time.Now().UTC()})
}

// isNotFound reports a delete of something already gone.
func isNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "no rows")
}
