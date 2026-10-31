package core_test

import (
	"path/filepath"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/core"
)

// TestExampleDecisions replays the calls of the example decision records
// through the subset and sensitivity checks, and compares what the core
// says with what the records say: the checks it ran, the reason, the tier
// and the action hash. Records list checks after a failure as skipped; the
// core stops at the failure, so only the checks it ran are compared.
func TestExampleDecisions(t *testing.T) {
	w := newWorld(t)
	grants := map[string]v0.Grant{}
	for _, f := range []string{"grant/pay-invoice.json", "grant/reconcile.json"} {
		g := load[v0.Grant](t, f)
		grants[g.ID] = g
	}
	files, _ := filepath.Glob("../../examples/v0/decision/*.json")
	if len(files) != 4 {
		t.Fatalf("%d example decisions", len(files))
	}
	for _, f := range files {
		d := load[v0.Decision](t, strings.TrimPrefix(f, "../../examples/v0/"))
		t.Run(filepath.Base(f), func(t *testing.T) {
			g, ok := grants[d.Grant.ID]
			if !ok {
				t.Fatalf("no example grant %s", d.Grant.ID)
			}
			args, _ := d.Request.Resource.Properties["arguments"].(map[string]any)
			call := core.Call{Resource: d.Request.Resource.ID, Action: d.Request.Action.Name, Arguments: args}
			hash, err := call.Hash()
			if err != nil {
				t.Fatal(err)
			}
			if hash != d.ActionHash {
				t.Errorf("action hash %s, the record says %s", hash, d.ActionHash)
			}
			op := core.Operation(w.manifests[call.Resource], call.Action)
			if op.Sensitivity != d.Sensitivity {
				t.Errorf("tier %s, the record says %s", op.Sensitivity, d.Sensitivity)
			}

			var ran []v0.Check
			var reason *v0.Reason
			hold := false
			check, reason := core.Subset(g, op, call)
			ran = append(ran, check)
			if reason == nil {
				check, reason, hold = core.Sensitivity(*op, v0.SensitivityCritical, core.Binding{}, hash)
				ran = append(ran, check)
			}

			outcome := v0.OutcomeAllow
			switch {
			case reason != nil:
				outcome = v0.OutcomeDeny
			case hold:
				outcome = v0.OutcomeApprovalRequired
			}
			if outcome != d.Outcome {
				t.Errorf("outcome %s, the record says %s", outcome, d.Outcome)
			}
			recorded := map[v0.CheckName]v0.Check{}
			for _, c := range d.Checks {
				recorded[c.Name] = c
			}
			for _, c := range ran {
				if r := recorded[c.Name]; r.Result != c.Result || r.Detail != c.Detail {
					t.Errorf("%s: core says %s %q, the record says %s %q", c.Name, c.Result, c.Detail, r.Result, r.Detail)
				}
			}
			switch {
			case reason == nil && len(d.Reasons) > 0:
				t.Errorf("no reason, the record gives %+v", d.Reasons)
			case reason != nil && (len(d.Reasons) != 1 || d.Reasons[0] != *reason):
				t.Errorf("reason %+v, the record gives %+v", *reason, d.Reasons)
			}
		})
	}
}

// TestExampleApprovals checks that each approval is bound to the hash of
// the action it shows the approvers.
func TestExampleApprovals(t *testing.T) {
	files, _ := filepath.Glob("../../examples/v0/approval/*.json")
	for _, f := range files {
		a := load[v0.Approval](t, strings.TrimPrefix(f, "../../examples/v0/"))
		if h, err := a.Action.Hash(); err != nil || h != a.ActionHash {
			t.Errorf("%s: action hashes to %s, the record says %s", filepath.Base(f), h, a.ActionHash)
		}
	}
}
