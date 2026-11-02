package configuration_test

import (
	"testing"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
)

func TestMayRequest(t *testing.T) {
	agent := func(s v0.AgentStatus, mandates ...string) v0.Agent {
		return v0.Agent{Spec: v0.AgentSpec{Status: s, Mandates: mandates}}
	}
	mandate := func(name string, open bool) v0.Mandate {
		return v0.Mandate{Metadata: v0.ObjectMeta{Name: name}, Spec: v0.MandateSpec{Open: open}}
	}
	for _, tc := range []struct {
		name string
		a    v0.Agent
		m    v0.Mandate
		want bool
	}{
		{"verified, listed", agent(v0.AgentVerified, "invoices"), mandate("invoices", false), true},
		{"verified, not listed", agent(v0.AgentVerified, "other"), mandate("invoices", false), false},
		{"verified, open", agent(v0.AgentVerified), mandate("readonly", true), true},
		{"unverified, open", agent(v0.AgentUnverified), mandate("readonly", true), true},
		{"unverified, listed but not open", agent(v0.AgentUnverified, "invoices"), mandate("invoices", false), false},
		{"suspended, open", agent(v0.AgentSuspended), mandate("readonly", true), false},
		{"suspended, listed", agent(v0.AgentSuspended, "invoices"), mandate("invoices", false), false},
	} {
		if got := configuration.MayRequest(tc.a, tc.m); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
