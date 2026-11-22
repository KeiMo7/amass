// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
)

// AddSource records src as a source of an entity.
func AddSource(ctx context.Context, sess et.Session, ent *dbt.Entity, src *et.Source) {
	if ent == nil || src == nil {
		return
	}
	_, _ = sess.DB().CreateEntityProperty(ctx, ent, &general.SourceProperty{
		Source:     src.Name,
		Confidence: src.Confidence,
	})
}

// AddProperty stores a simple property on an entity.
func AddProperty(ctx context.Context, sess et.Session, ent *dbt.Entity, name, value string) {
	if ent == nil || name == "" || value == "" {
		return
	}
	_, _ = sess.DB().CreateEntityProperty(ctx, ent, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

// AddEdgeProperty stores a simple property on an edge, such as the role or
// field that qualifies a relation.
func AddEdgeProperty(ctx context.Context, sess et.Session, edge *dbt.Edge, name, value string) {
	if edge == nil || name == "" || value == "" {
		return
	}
	_, _ = sess.DB().CreateEdgeProperty(ctx, edge, &general.SimpleProperty{PropertyName: name,
		PropertyValue: value})
}

// Link creates a simple relation labeled label from one entity to another
// with src as its source, and returns the edge, or nil when it was not
// created.
func Link(ctx context.Context, sess et.Session, from *dbt.Entity, label string, to *dbt.Entity,
	src *et.Source) *dbt.Edge {
	if from == nil || to == nil {
		return nil
	}
	edge, err := sess.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return nil
	}
	if src != nil {
		_, _ = sess.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
	}
	return edge
}
