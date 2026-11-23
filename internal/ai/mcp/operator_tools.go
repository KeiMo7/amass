// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	lenscli "github.com/owasp-amass/amass/v5/internal/lens/cli"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// operatorCapabilities returns the operator tools as capabilities. Every one
// is operator tier, so the registry serves them only to a connection acting
// as an operator. The tools that collect data or write to the database declare
// their approval step (approve) rather than calling gate themselves, so the
// framework enforces consent; review_proposal keeps its own handler because it
// gates only the decisions that write (approve and retract), not a rejection.
func operatorCapabilities(op *Operator, runner ai.ToolRunner) []capability {
	var caps []capability
	target := map[string]any{"type": "string",
		"description": "The exact target: a domain (example.com), an IP address, a CIDR range or an AS number (AS15169)"}
	mode := map[string]any{"type": "string", "enum": []string{string(collect.Passive), string(collect.Active)},
		"description": "passive (default) queries data sources only; active also probes the target's hosts"}
	also := map[string]any{"type": "array", "maxItems": collect.MaxAlso,
		"items": map[string]any{"type": "string"},
		"description": "More targets in scope for the same run, each a domain, an IP address, a CIDR range or an " +
			"AS number, such as the organization's own netblocks and AS"}
	expand := map[string]any{"type": "boolean",
		"description": "Allow scope expansion: domains, netblocks and ASes the engine attributes to the targets' " +
			"organization while it runs are collected too (default false: only the listed targets)"}
	bruteForce := map[string]any{"type": "boolean",
		"description": "Turn on DNS brute forcing: guess subdomain names from a wordlist (active mode only, " +
			"default false). Off unless the user asks for it; it greatly increases the work and the queries sent."}
	alterations := map[string]any{"type": "boolean",
		"description": "Turn on name alterations: permute discovered names to find more (active mode only, " +
			"default false). Off unless the user asks for it."}
	iface := map[string]any{"type": "string", "maxLength": 64,
		"description": "Network interface on the engine's host for the run's traffic: an interface name such as " +
			"eth0, or one of the host's IP addresses (default: the engine's own setting). Only when the user asks."}
	activeRoute := map[string]any{"type": "string", "maxLength": 256,
		"description": "Route for the run's active traffic (active mode only): an interface on the engine's host, " +
			"or a proxy URL such as socks5h://tor:9050 (socks5h, socks5 or http CONNECT). Active traffic never " +
			"falls back to a direct connection. Never include a password; that belongs in the configuration. " +
			"Only when the user asks."}
	activeUDPRoute := map[string]any{"type": "string", "maxLength": 64,
		"description": "Interface for active UDP when active_route is a proxy, which carries TCP only. Only when " +
			"the user asks."}
	phone := map[string]any{"type": "string",
		"description": "Pivot from a phone number instead of a target: resolve the organizations tied to it and " +
			"enumerate their registered domains. Give one of target, phone or address."}
	address := map[string]any{"type": "string",
		"description": "Pivot from a street address instead of a target: resolve the organizations at it and " +
			"enumerate their registered domains. A shared or registered-agent address is held for review, not " +
			"enumerated. Give one of target, phone or address."}
	obj := func(required []string, props map[string]any) map[string]any {
		schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			// Clients reject a null required list.
			schema["required"] = required
		}

		return schema
	}

	// add declares a tool that runs directly; a handler error is returned to the
	// model as a tool result, as before.
	add := func(name, title, desc string, schema map[string]any, ann *mcp.ToolAnnotations,
		h func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error)) {
		ann.Title = title
		caps = append(caps, capability{tier: tierOperator,
			tool: &mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: ann},
			handle: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args json.RawMessage
				if req.Params != nil {
					args = req.Params.Arguments
				}

				res, err := h(ctx, req, args)
				if err != nil {
					return errorResult(err), nil
				}

				return res, nil
			}})
	}
	// approveAction declares a tool whose action always needs the user's
	// consent: h validates the call and returns the approval message and the
	// act to run, and the registry passes both to gate.
	approveAction := func(name, title, desc string, schema map[string]any, ann *mcp.ToolAnnotations,
		h func(context.Context, *mcp.CallToolRequest, json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error)) {
		ann.Title = title
		caps = append(caps, capability{tier: tierOperator,
			tool:    &mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: ann},
			approve: h})
	}
	readOnly := func() *mcp.ToolAnnotations {
		return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}
	}

	add(ToolPlanEnumeration, "Plan an Amass enumeration",
		"Show what an enumeration would do, without starting it: the scope (one target, any more targets in also, "+
			"and whether it may expand), the methods, their effects, and the plan_id that start_enumeration needs. "+
			"Instead of a target you may give a phone or address to pivot from: the plan then lists the "+
			"organizations the seed resolved to and enumerates their registered domains.",
		obj(nil, map[string]any{"target": target, "mode": mode, "also": also, "expand": expand,
			"brute_force": bruteForce, "alterations": alterations, "interface": iface, "active_route": activeRoute,
			"active_udp_route": activeUDPRoute, "phone": phone, "address": address}),
		readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				Phone   string
				Address string
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if err := oneSeed(a.Target, a.Phone, a.Address); err != nil {
				return nil, err
			}

			plan, err := enumerationPlan(ctx, runner, a.Target, a.Phone, a.Address, a.Mode, a.Also,
				a.options())
			if err != nil {
				return nil, err
			}
			if plan.Status != collect.StatusApprovalRequired {
				// A pivot that resolved organizations but cannot be enumerated
				// (a shared address, or no domains yet) still shows them, so the
				// user can pick a target; a direct target that is unsupported is
				// an error as before.
				if plan.Pivot != nil {
					return jsonResult(map[string]any{"plan": plan, "next": plan.Reason}), nil
				}
				return nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}

			next := "Show the user the scope and effects, then call start_enumeration with the same target, " +
				"mode, also, expand, brute_force, alterations, interface and active routes, and this plan_id. The user " +
				"is asked to approve it."
			if plan.Pivot != nil {
				next = "Show the user the phone/address, the organizations it resolved to and the domains to be " +
					"enumerated, then call start_enumeration with the same phone or address, mode, expand, " +
					"brute_force, alterations, interface and active routes, and this plan_id. The user is asked to approve it."
			}
			return jsonResult(map[string]any{"plan": plan, "next": next}), nil
		})

	approveAction(ToolStartEnumeration, "Start an Amass enumeration",
		"Start the enumeration a plan_enumeration call described. Collects data from the Internet about the "+
			"target and stores it in the Asset Database; the user is asked to approve it first.",
		obj([]string{"plan_id"}, map[string]any{"target": target, "mode": mode, "also": also,
			"expand": expand, "brute_force": bruteForce, "alterations": alterations, "interface": iface,
			"active_route": activeRoute, "active_udp_route": activeUDPRoute, "phone": phone, "address": address,
			"plan_id": map[string]any{
				"type":        "string",
				"description": "The plan_id plan_enumeration returned",
			}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				Phone   string
				Address string
				PlanID  string `json:"plan_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if err := oneSeed(a.Target, a.Phone, a.Address); err != nil {
				return "", nil, err
			}
			if op.Collect == nil {
				return "", nil, errors.New("this server cannot start enumerations: no engine is configured")
			}

			plan, err := enumerationPlan(ctx, runner, a.Target, a.Phone, a.Address, a.Mode, a.Also,
				a.options())
			if err != nil {
				return "", nil, err
			}
			if plan.Status != collect.StatusApprovalRequired {
				return "", nil, errors.New("cannot enumerate this: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return "", nil, errors.New("plan_id does not match this request; call plan_enumeration again and " +
					"show the user the new plan (a pivot's resolved domains can change as data is collected)")
			}

			msg := fmt.Sprintf("Start a %s?\n\n%s", plan.Summary(), plan.Effects)
			if plan.Pivot != nil {
				msg = fmt.Sprintf("Start a %s?\n\n%s\n\n%s", plan.Summary(), pivotApprovalText(plan.Pivot),
					plan.Effects)
			}
			return msg, func(via string) (*mcp.CallToolResult, error) {
				sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
				defer cancel()
				run, err := op.Collect.Start(sctx, plan, approver(req, via))
				if err != nil {
					return nil, err
				}

				return jsonResult(map[string]any{"run": run,
					"next": "Check progress with enumeration_status; runs end on their own when the work is done."}), nil
			}, nil
		})

	add(ToolEnumerationStatus, "Amass enumeration status",
		"Show the enumerations this server started: state, progress and, for a finished run, what it found. "+
			"Without run_id, lists every run.",
		obj(nil, map[string]any{"run_id": map[string]any{"type": "string"}}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}
			if op.Collect == nil {
				return nil, errors.New("no engine is configured")
			}
			if a.RunID == "" {
				return jsonResult(map[string]any{"runs": op.Collect.Runs()}), nil
			}

			run, ok := op.Collect.Get(a.RunID)
			if !ok {
				return nil, fmt.Errorf("no enumeration run %s", a.RunID)
			}

			out := map[string]any{"run": run}
			if run.Finished() && runner.Graph != nil {
				out["found"] = foundSince(ctx, runner, run)
			}
			// Surface the proposals awaiting review and the decisions the
			// classifier applied, so the assistant can present them without the
			// user knowing to ask. Reported while the run is still going too (the
			// incremental attribution pass records them mid-run), so a watching
			// assistant can raise them in near real time, not only at the end.
			if op.Journal != "" {
				// Both counts cover this run only; list_proposals with pending
				// true shows the journal's whole backlog.
				if s, err := lenscli.PendingProposalsSince(op.Journal, run.StartedAt); err == nil && s.Total > 0 {
					out["pending_proposals"] = s
				}
				// Surface what the classifier applied automatically during this
				// run, so the assistant can tell the user what the AI decided on
				// its own, not only what awaits review.
				if a, err := lenscli.AppliedByAISummary(op.Journal, run.StartedAt); err == nil && a.Total > 0 {
					out["applied_by_ai"] = a
				}
			}

			return jsonResult(out), nil
		})

	add(ToolStopEnumeration, "Stop an Amass enumeration", "End a running enumeration and its engine session.",
		obj([]string{"run_id"}, map[string]any{"run_id": map[string]any{"type": "string"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				RunID string `json:"run_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Collect == nil {
				return nil, errors.New("no engine is configured")
			}

			run, err := op.Collect.Stop(ctx, a.RunID)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"run": run}), nil
		})

	approveAction(ToolWatchTarget, "Watch a target with Amass",
		"Re-run the enumeration a plan_enumeration call described on a schedule, so changes to the target are "+
			"collected without asking each time. The user approves the watch once; it runs until stop_watch.",
		obj([]string{"target", "plan_id", "every_hours"}, map[string]any{"target": target, "mode": mode,
			"also": also, "expand": expand, "brute_force": bruteForce, "alterations": alterations,
			"interface": iface, "active_route": activeRoute, "active_udp_route": activeUDPRoute,
			"plan_id": map[string]any{
				"type":        "string",
				"description": "The plan_id plan_enumeration returned",
			},
			"every_hours": map[string]any{"type": "integer", "minimum": int(collect.MinWatchInterval.Hours()),
				"maximum": 24 * 90, "description": "Hours between runs, such as 24 for daily or 168 for weekly"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(_ context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Target string
				Mode   string
				Also   []string
				planArgs
				PlanID     string `json:"plan_id"`
				EveryHours int    `json:"every_hours"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if op.Watches == nil {
				return "", nil, errors.New("this server cannot keep watches")
			}

			plan := planFor(a.Target, a.Mode, a.Also, a.options())
			if plan.Status != collect.StatusApprovalRequired {
				return "", nil, errors.New("cannot enumerate this target: " + plan.Reason)
			}
			if a.PlanID != plan.ID {
				return "", nil, errors.New("plan_id does not match this target, mode, also, expand, brute_force, " +
					"alterations, interface and active routes; call plan_enumeration again")
			}

			every := time.Duration(a.EveryHours) * time.Hour
			msg := fmt.Sprintf("Run a %s every %d hours, starting now, until the watch is stopped?\n\n%s",
				plan.Summary(), a.EveryHours, plan.Effects)
			return msg, func(via string) (*mcp.CallToolResult, error) {
				w, err := op.Watches.Add(plan, every, approver(req, via))
				if err != nil {
					return nil, err
				}

				return jsonResult(map[string]any{"watch": w,
					"next": "The first run starts within a minute. list_watches shows what each run found."}), nil
			}, nil
		})

	add(ToolListWatches, "Amass watches",
		"List the scheduled enumerations: their scope, schedule, next run, and what the last finished run found.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}

			return jsonResult(map[string]any{"watches": op.Watches.List()}), nil
		})

	approveAction(ToolReadDocuments, "Read documents with the document model",
		"Have the document model named in the options.ai.documents configuration read the documents a domain or "+
			"organization publishes, all of each document's text (fetched again, from the archive copy the engine "+
			"read when it read one; the database keeps no copy), and store what they state in Open Asset Model "+
			"terms (assets, relations, field values) as amass-ai observations, undoable. Each finding is checked "+
			"against the text: its quote is in the document, its names are written there, its types and relations "+
			"are ones OAM allows, and a relation is not negated. Each version of a document is read once. Reads at "+
			"most max_documents (default 2) per call; call again while remaining is above zero. The document "+
			"text goes to that model only; the result holds counts unless the configuration shares documents "+
			"with assistants.",
		obj(nil, map[string]any{
			"domain": map[string]any{"type": "string", "description": "The domain whose documents are read"},
			"organization": map[string]any{"type": "string",
				"description": "Instead of a domain, the exact name of a stored organization"},
			"max_documents": map[string]any{"type": "integer", "minimum": 1, "maximum": maxDocumentsPerCall,
				"description": "Most documents read in this call (default 2)"},
			"dry_run": map[string]any{"type": "boolean",
				"description": "Read and validate without storing anything"},
			"reread": map[string]any{"type": "boolean",
				"description": "Read documents again even when their version was read, undoing the earlier findings"},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), OpenWorldHint: boolPtr(true)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Domain       string
				Organization string
				MaxDocuments int  `json:"max_documents"`
				DryRun       bool `json:"dry_run"`
				Reread       bool
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}

			model, modelID, timeout, err := ai.DocumentModel(op.Documents)
			if err != nil {
				return "", nil, err
			}
			if op.Graph.Repo == nil {
				return "", nil, errors.New("no Asset Database is open")
			}
			// the document model's findings are read as stored; this graph is
			// never handed to the client
			dg := op.Graph
			dg.WithholdDocumentText = false
			root, err := ai.DocumentRoot(ctx, dg, a.Domain, a.Organization)
			if err != nil {
				return "", nil, err
			}
			limit := a.MaxDocuments
			if limit <= 0 {
				limit = defaultDocumentsPerCall
			}
			limit = min(limit, maxDocumentsPerCall)

			action := "store the statements it finds on them as amass-ai observations"
			if a.DryRun {
				action = "check the statements it finds without storing them"
			}
			msg := fmt.Sprintf("Fetch up to %d documents published by %s and send their full text to the document "+
				"model %s, and %s?", limit, graph.AssetLabel(root), modelID, action)
			return msg, func(via string) (*mcp.CallToolResult, error) {
				run, err := ai.ReadDocuments(ctx, dg, op.Graph.Repo, &review.Journal{Path: op.Journal}, root,
					ai.DocumentRunOptions{Model: model, ModelID: modelID, ModelTimeout: timeout,
						ChunkChars: op.Documents.ChunkChars, Max: limit,
						Reread: a.Reread, DryRun: a.DryRun, Actor: approver(req, via)})
				if err != nil {
					return nil, err
				}

				result := map[string]any{"run": run}
				if op.ShareDocuments {
					stored := map[string][]review.StoredStatement{}
					for _, d := range run.Documents {
						if len(d.Stored) > 0 {
							stored[d.URL] = d.Stored
						}
					}
					result["statements"] = stored
				}
				if run.Remaining > 0 {
					result["next"] = fmt.Sprintf("%d documents remain; call read_documents again to read them.",
						run.Remaining)
				}
				return jsonResult(result), nil
			}, nil
		})

	add(ToolStopWatch, "Stop an Amass watch", "Remove a scheduled enumeration; a run it started finishes on its own.",
		obj([]string{"watch_id"}, map[string]any{"watch_id": map[string]any{"type": "string"}}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: boolPtr(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				WatchID string `json:"watch_id"`
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Watches == nil {
				return nil, errors.New("this server cannot keep watches")
			}

			w, err := op.Watches.Remove(a.WatchID)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"removed": w}), nil
		})

	add(ToolListProposals, "Amass review proposals",
		"List the proposals awaiting review: ownership relationships, organization merges, identity corrections "+
			"and organizations recorded under a person's name, each with its ID, evidence and status. Set "+
			"\"pending\" to list only the proposals still awaiting a decision, so newly-proposed items can be "+
			"surfaced for the user to decide on immediately.",
		obj(nil, map[string]any{
			"pending": map[string]any{"type": "boolean",
				"description": "List only proposals that are still awaiting a decision."},
			"applied": map[string]any{"type": "boolean",
				"description": "List instead the changes the AI classifier applied automatically."},
			"lead": map[string]any{"type": "string",
				"description": "Show one document lead (doclead:<run>:<entity>, as applied lists them) instead: " +
					"its document, how it settled and, when confirmed, each asset it led to."},
		}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Journal == "" {
				return nil, errors.New("no review journal is configured")
			}

			var a struct {
				Pending bool   `json:"pending"`
				Applied bool   `json:"applied"`
				Lead    string `json:"lead"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}

			if a.Lead != "" {
				if runner.Graph == nil {
					return nil, errors.New("no asset database is open")
				}
				text, err := lenscli.LeadFootprintText(op.Journal, a.Lead, func(id string) (graph.Asset, bool) {
					asset, err := runner.Graph.GetAsset(ctx, id)
					return asset, err == nil
				})
				if err != nil {
					return nil, err
				}
				return textResult(text), nil
			}

			text, err := lenscli.ProposalsText(op.Journal)
			switch {
			case a.Applied:
				text, err = lenscli.AppliedProposalsTextLive(op.Journal, entityExists(ctx, runner.Graph))
			case a.Pending:
				text, err = lenscli.PendingProposalsTextLive(op.Journal, entityExists(ctx, runner.Graph))
			}
			if err != nil {
				return nil, err
			}

			return textResult(text), nil
		})

	add(ToolWatchDecisions, "Watch Amass decisions",
		"Wait for new review items while an enumeration runs: proposals that now await the user's decision and "+
			"changes the AI classifier applied on its own (ownership edges, organization merges, identity "+
			"corrections, scope expansions, document leads). Call it first without a cursor to start from now; then pass the "+
			"cursor it returns. Each call returns as soon as new items are written, or after wait_seconds with "+
			"none, with the cursor for the next call. Reads the review journal only; it changes nothing.",
		obj(nil, map[string]any{
			"cursor": map[string]any{"type": "string",
				"description": "The cursor a previous call returned; omit to start from now."},
			"wait_seconds": map[string]any{"type": "integer", "minimum": 0, "maximum": maxDecisionWait,
				"description": fmt.Sprintf("How long to wait for new items (default %d, at most %d).",
					defaultDecisionWait, maxDecisionWait)},
		}), readOnly(),
		func(ctx context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			if op.Journal == "" {
				return nil, errors.New("no review journal is configured")
			}
			if !op.AnnounceDecisions {
				return textResult("Decision announcements are turned off (attribution is off, or " +
					"AMASS_AI_ANNOUNCE_DECISIONS is false). list_proposals still lists proposals and applied " +
					"changes on request."), nil
			}

			var a struct {
				Cursor string `json:"cursor"`
				Wait   *int   `json:"wait_seconds"`
			}
			if len(raw) > 0 {
				if err := json.Unmarshal(raw, &a); err != nil {
					return nil, err
				}
			}

			wait := defaultDecisionWait
			if a.Wait != nil {
				wait = min(max(*a.Wait, 0), maxDecisionWait)
			}

			return watchDecisions(ctx, op.Journal, a.Cursor, time.Duration(wait)*time.Second,
				entityExists(ctx, runner.Graph))
		})

	add(ToolReviewProposal, "Review an Amass proposal",
		"Approve, reject or retract one proposal by ID. Approving writes its relationship, merge or correction to "+
			"the Asset Database and retracting removes it; the user is asked first. Rejecting only records the decision.",
		obj([]string{"proposal_id", "decision"}, map[string]any{
			"proposal_id": map[string]any{"type": "string"},
			"decision": map[string]any{"type": "string",
				"enum": []string{lenscli.DecisionApprove, lenscli.DecisionReject, lenscli.DecisionRetract}},
		}),
		&mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(false)},
		func(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct {
				ProposalID string `json:"proposal_id"`
				Decision   string
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.Journal == "" {
				return nil, errors.New("no review journal is configured")
			}

			decide := func(via string) (*mcp.CallToolResult, error) {
				dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
				defer cancel()
				text, err := lenscli.Decide(dctx, op.Graph, op.Journal, a.Decision, a.ProposalID, approver(req, via))
				if err != nil {
					return nil, err
				}

				return textResult(text), nil
			}
			if a.Decision == lenscli.DecisionReject || a.Decision == "" {
				return decide("no write")
			}

			msg := fmt.Sprintf("%s proposal %s? This changes the Asset Database.",
				strings.ToUpper(a.Decision[:1])+a.Decision[1:], a.ProposalID)
			return op.gate(req, msg, decide)
		})

	add(ToolDataSources, "Amass data sources",
		"List the data sources the enumeration engine can use and whether each has credentials configured. "+
			"Never shows the credentials.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			if op.DataSources == "" {
				return nil, errors.New("no datasources file is configured")
			}

			st, err := collect.DataSourceStatus(op.DataSources)
			if err != nil {
				return nil, err
			}

			var with, without []string
			for _, s := range st {
				if s.Configured {
					with = append(with, s.Name)
				} else {
					without = append(without, s.Name)
				}
			}

			return jsonResult(map[string]any{"configured": with, "without_credentials": without,
				"note": "Sources without credentials are skipped. Use data_source_key_link to let the user add a key."}), nil
		})

	add(ToolDataSourceKey, "Link to add a data source key",
		"Create a one-time local link where the user enters credentials for one data source. The credentials go "+
			"straight from the user's browser to the datasources file, never through this conversation.",
		obj([]string{"source"}, map[string]any{"source": map[string]any{"type": "string",
			"description": "The data source name as data_sources lists it"}}),
		&mcp.ToolAnnotations{OpenWorldHint: boolPtr(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct{ Source string }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.KeyLinks == nil || op.DataSources == "" {
				return nil, errors.New("this connection cannot serve key links; add the key to the datasources " +
					"file (config/datasources.yaml in the Compose stack)")
			}

			link, expires, err := op.KeyLinks.New(a.Source)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"url": link, "expires": expires.Format(time.RFC3339),
				"next": "Give the user this link to open in a browser on the computer running Amass. It works once."}), nil
		})

	return caps
}
