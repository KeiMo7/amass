// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
)

// Without ai.documents no model reads documents: the main model is never a
// fallback.
func TestDocumentModelHasNoFallback(t *testing.T) {
	for _, d := range []*config.DocumentModelSettings{nil, {Provider: "ollama", Model: "qwen3:8b"}} {
		if _, _, _, err := documentModel(d); err == nil || !strings.Contains(err.Error(), "ai.documents") {
			t.Fatalf("documentModel(%+v) = %v, want an ai.documents error", d, err)
		}
	}

	m, id, timeout, err := documentModel(&config.DocumentModelSettings{Enabled: true, Provider: "Ollama",
		Endpoint: "http://ollama:11434", Model: "qwen3:8b", AllowHTTP: true, ModelTimeout: "4m"})
	if err != nil || m == nil {
		t.Fatalf("documentModel: %v", err)
	}
	if id != "ollama/qwen3:8b" || timeout != 4*time.Minute {
		t.Fatalf("model %q, timeout %v", id, timeout)
	}

	// a plain HTTP endpoint needs allow_http, as for the main model
	if _, _, _, err := documentModel(&config.DocumentModelSettings{Enabled: true, Provider: "compatible",
		Endpoint: "http://10.0.0.5:8000/v1/chat/completions", Model: "m"}); err == nil {
		t.Fatal("plain HTTP endpoint accepted without allow_http")
	}
}
