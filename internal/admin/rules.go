package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

	v0 "github.com/vladmsnk/agentbox/api/v0"
	"github.com/vladmsnk/agentbox/internal/policy"
	"github.com/vladmsnk/agentbox/internal/store"
)

// The rules that span documents. Each document's own schema and Check have
// already passed; these look at the others: do the operations a mandate
// names exist, does a mandate lie within every agent that may hold it, is
// an identity claimed twice. They run on every write, so the database never
// holds a configuration that contradicts itself.

// Problems is a validation failure with one line per rule broken.
type Problems []string

func (p Problems) Error() string {
	if len(p) == 1 {
		return p[0]
	}
	return fmt.Sprintf("%d problems: %s", len(p), p[0])
}

// snapshot is the current, enabled configuration, loaded once per write.
type snapshot struct {
	manifests map[string]v0.Manifest // by name
	byAud     map[string]v0.Manifest // by audience
	agents    map[string]v0.Agent
	mandates  map[string]v0.Mandate
	secrets   map[string]bool
}

func load(ctx context.Context, st store.Store) (*snapshot, error) {
	docs := st.Documents()
	s := &snapshot{
		manifests: map[string]v0.Manifest{}, byAud: map[string]v0.Manifest{},
		agents: map[string]v0.Agent{}, mandates: map[string]v0.Mandate{}, secrets: map[string]bool{},
	}
	secretList, err := st.Secrets().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, sec := range secretList {
		s.secrets[sec.Name] = true
	}
	manifests, err := enabled(ctx, docs, v0.KindManifest)
	if err != nil {
		return nil, err
	}
	agents, err := enabled(ctx, docs, v0.KindAgent)
	if err != nil {
		return nil, err
	}
	mandates, err := enabled(ctx, docs, v0.KindMandate)
	if err != nil {
		return nil, err
	}
	for _, d := range manifests {
		var m v0.Manifest
		if err := json.Unmarshal(d.Doc, &m); err != nil {
			return nil, err
		}
		s.manifests[d.Name] = m
		s.byAud[m.Spec.Audience] = m
	}
	for _, d := range agents {
		var a v0.Agent
		if err := json.Unmarshal(d.Doc, &a); err != nil {
			return nil, err
		}
		s.agents[d.Name] = a
	}
	for _, d := range mandates {
		var m v0.Mandate
		if err := json.Unmarshal(d.Doc, &m); err != nil {
			return nil, err
		}
		s.mandates[d.Name] = m
	}
	return s, nil
}

// enabled returns the enabled current documents of a kind; a disabled
// document does not take part in any rule.
func enabled(ctx context.Context, docs store.Documents, kind string) ([]store.Document, error) {
	all, err := docs.List(ctx, kind)
	if err != nil {
		return nil, err
	}
	var out []store.Document
	for _, d := range all {
		if !d.Disabled {
			out = append(out, d)
		}
	}
	return out, nil
}

// declared reports whether the manifest for location gives action the
// argument field. An unknown manifest or operation is reported elsewhere;
// here it counts as declared so the message is not repeated.
func (s *snapshot) declared(location, action, field string) bool {
	man, ok := s.byAud[location]
	if !ok {
		return true
	}
	op, ok := findOp(man, action)
	if !ok {
		return true
	}
	_, has := op.Params[field]
	return has
}

// checkManifest: one manifest per audience, and the upstream's secret
// exists before the manifest can rely on it.
func (s *snapshot) checkManifest(m v0.Manifest) Problems {
	var p Problems
	if other, ok := s.byAud[m.Spec.Audience]; ok && other.Metadata.Name != m.Metadata.Name {
		p = append(p, fmt.Sprintf("audience %s already belongs to manifest %s", m.Spec.Audience, other.Metadata.Name))
	}
	if a := m.Spec.Upstream.Auth; a != nil && !s.secrets[a.SecretRef] {
		p = append(p, fmt.Sprintf("manifest %s names secret %s, which has not been stored; put it first", m.Metadata.Name, a.SecretRef))
	}
	return p
}

// secretUsers names the enabled manifests whose upstream uses a secret.
func (s *snapshot) secretUsers(name string) []string {
	var out []string
	for _, mn := range sortedManifestNames(s.manifests) {
		if a := s.manifests[mn].Spec.Upstream.Auth; a != nil && a.SecretRef == name {
			out = append(out, mn)
		}
	}
	return out
}

func sortedManifestNames(m map[string]v0.Manifest) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// checkMandate: every operation exists, and the mandate lies within every
// agent that may hold it.
func (s *snapshot) checkMandate(m v0.Mandate) Problems {
	var p Problems
	p = append(p, s.operationsExist(m.Spec.Permissions, "mandate "+m.Metadata.Name)...)
	p = append(p, policy.Coherent(m.Spec.Permissions, "mandate "+m.Metadata.Name)...)
	for _, name := range sortedAgentNames(s.agents) {
		a := s.agents[name]
		if slices.Contains(a.Spec.Mandates, m.Metadata.Name) || (m.Spec.Open && a.Spec.Status == v0.AgentUnverified) {
			p = append(p, s.mandateWithinAgent(m, a)...)
		}
	}
	return p
}

// checkAgent: the mandates it lists exist and lie within it, and no other
// agent claims one of its identities.
func (s *snapshot) checkAgent(a v0.Agent) Problems {
	var p Problems
	for _, name := range a.Spec.Mandates {
		m, ok := s.mandates[name]
		if !ok {
			p = append(p, fmt.Sprintf("agent %s lists mandate %s, which does not exist", a.Metadata.Name, name))
			continue
		}
		p = append(p, s.mandateWithinAgent(m, a)...)
	}
	if a.Spec.Status == v0.AgentUnverified {
		for _, name := range sortedMandateNames(s.mandates) {
			if m := s.mandates[name]; m.Spec.Open {
				p = append(p, s.mandateWithinAgent(m, a)...)
			}
		}
	}
	p = append(p, s.operationsExist(a.Spec.Permissions, "agent "+a.Metadata.Name)...)
	p = append(p, policy.Coherent(a.Spec.Permissions, "agent "+a.Metadata.Name)...)
	for _, other := range s.agents {
		if other.Metadata.Name == a.Metadata.Name {
			continue
		}
		for _, id := range a.Spec.Identities {
			for _, oid := range other.Spec.Identities {
				if sameIdentity(id, oid) {
					p = append(p, fmt.Sprintf("identity %s is already claimed by agent %s", describe(id), other.Metadata.Name))
				}
			}
		}
	}
	return p
}

func (s *snapshot) mandateWithinAgent(m v0.Mandate, a v0.Agent) Problems {
	mn, an := "mandate "+m.Metadata.Name, "agent "+a.Metadata.Name
	p := Problems(policy.Within(m.Spec.Permissions, mn, a.Spec.Permissions, an, s.declared))
	if m.Spec.TTL.D() > a.Spec.MaxTTL.D() {
		p = append(p, fmt.Sprintf("%s has ttl %s, longer than %s's max_ttl %s", mn, m.Spec.TTL, an, a.Spec.MaxTTL))
	}
	for _, perm := range m.Spec.Permissions {
		for _, loc := range perm.Locations {
			man, ok := s.byAud[loc]
			if !ok {
				continue // reported by operationsExist
			}
			for _, act := range perm.Actions {
				if op, ok := findOp(man, act); ok && policy.Tier(op.Sensitivity) > policy.Tier(a.Spec.MaxSensitivity) {
					p = append(p, fmt.Sprintf("%s allows %s, a %s operation, but %s may go no higher than %s", mn, act, op.Sensitivity, an, a.Spec.MaxSensitivity))
				}
			}
		}
	}
	for _, ml := range m.Spec.Limits {
		for _, al := range a.Spec.Limits {
			if ml.Name != al.Name {
				continue
			}
			if ml.Kind != al.Kind || ml.Field != al.Field {
				p = append(p, fmt.Sprintf("limit %s is %s of %s in %s but %s of %s in %s", ml.Name, ml.Kind, ml.Field, mn, al.Kind, al.Field, an))
			} else if ml.Max > al.Max {
				p = append(p, fmt.Sprintf("limit %s is %v in %s but %s caps it at %v", ml.Name, ml.Max, mn, an, al.Max))
			}
		}
	}
	return p
}

// operationsExist: every location is a manifest's audience and every action
// one of its operations.
func (s *snapshot) operationsExist(perms []v0.Permission, who string) Problems {
	var p Problems
	for _, perm := range perms {
		for _, loc := range perm.Locations {
			man, ok := s.byAud[loc]
			if !ok {
				p = append(p, fmt.Sprintf("%s names %s, which no manifest declares", who, loc))
				continue
			}
			for _, act := range perm.Actions {
				if _, ok := findOp(man, act); !ok {
					p = append(p, fmt.Sprintf("%s names operation %s, which manifest %s does not declare", who, act, man.Metadata.Name))
				}
			}
			// A bound applies to the operations that have the argument; a
			// bound none of them has is a mistake, usually a typo.
			for _, field := range sortedFields(perm.Constraints) {
				declaredSomewhere := false
				for _, act := range perm.Actions {
					if op, ok := findOp(man, act); ok {
						if _, has := op.Params[field]; has {
							declaredSomewhere = true
						}
					}
				}
				if !declaredSomewhere {
					p = append(p, fmt.Sprintf("%s constrains %s, which none of its operations at %s has", who, field, loc))
				}
			}
		}
	}
	return p
}

// dependents names the enabled mandates that reference a manifest's
// audience, for refusing to disable it under them.
func (s *snapshot) dependents(audience string) []string {
	var out []string
	for _, name := range sortedMandateNames(s.mandates) {
		for _, perm := range s.mandates[name].Spec.Permissions {
			if slices.Contains(perm.Locations, audience) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

func findOp(m v0.Manifest, name string) (v0.Operation, bool) {
	for _, op := range m.Spec.Operations {
		if op.Name == name {
			return op, true
		}
	}
	return v0.Operation{}, false
}

func sameIdentity(a, b v0.AgentIdentity) bool {
	if a.Type != b.Type {
		return false
	}
	switch a.Type {
	case v0.IdentityOAuthClient:
		return a.ClientID == b.ClientID
	case v0.IdentityJWT:
		return a.Issuer == b.Issuer && a.Subject == b.Subject
	}
	return false
}

func describe(id v0.AgentIdentity) string {
	switch id.Type {
	case v0.IdentityOAuthClient:
		return "oauth_client " + id.ClientID
	case v0.IdentityJWT:
		return "jwt " + id.Issuer + " " + id.Subject
	}
	return string(id.Type)
}

func sortedFields(m map[string]v0.Constraint) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedAgentNames(m map[string]v0.Agent) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedMandateNames(m map[string]v0.Mandate) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// IsProblems reports whether err is a validation failure, for the HTTP
// layer to turn into a 400.
func IsProblems(err error) (Problems, bool) {
	var p Problems
	if errors.As(err, &p) {
		return p, true
	}
	return nil, false
}
