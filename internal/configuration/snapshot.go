// Package configuration is everything about the documents that configure
// doorward: Manifests, Agents and Mandates, every version of them, and the
// sealed secrets they name. It keeps them (Manager, SecretManager), keeps a
// decision point's decoded copy current (Cache, Snapshot), checks the rules
// that span documents before a change is accepted, and serves the Admin API
// that changes them.
package configuration

import (
	"errors"
	"sort"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/x"
)

// ErrBroken marks a document this version of doorward cannot read: it
// carries a field this version does not know, or breaks a rule. Calls that
// depend on it are refused until the instance is upgraded or the document
// repaired; an older instance never enforces less than it should.
var ErrBroken = errors.New("configuration document cannot be read by this version")

// Manifest is an enabled manifest with the version digest records name.
type Manifest struct {
	v0.Manifest
	Digest string
}

// Mandate is a mandate, enabled or not, with its version digest.
type Mandate struct {
	v0.Mandate
	Digest   string
	Disabled bool
}

// Agent is an agent with its version digest.
type Agent struct {
	v0.Agent
	Digest string
}

// Snapshot is the configuration as of one version.
type Snapshot struct {
	Version   uint64
	manifests map[string]Manifest // by audience
	mandates  map[string]Mandate  // by name
	agents    map[string]Agent    // by name
	broken    map[string]error    // kind/name of documents that did not decode
}

// ManifestFor returns the enabled manifest whose audience is location, and
// false when no manifest declares it.
func (s *Snapshot) ManifestFor(location string) (Manifest, bool, error) {
	m, ok := s.manifests[location]
	if !ok {
		if err := s.brokenFor(v0.KindManifest, location); err != nil {
			return Manifest{}, false, err
		}
	}
	return m, ok, nil
}

// ManifestByName returns an enabled manifest by its name.
func (s *Snapshot) ManifestByName(name string) (Manifest, bool) {
	for _, m := range s.manifests {
		if m.Metadata.Name == name {
			return m, true
		}
	}
	return Manifest{}, false
}

// MandatesWhere names the enabled mandates keep selects, sorted.
func (s *Snapshot) MandatesWhere(keep func(v0.Mandate) bool) []string {
	var out []string
	for name, m := range s.mandates {
		if !m.Disabled && keep(m.Mandate) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// Mandate returns a mandate by name; x.ErrNotFound when there is none.
func (s *Snapshot) Mandate(name string) (Mandate, error) {
	return byName(s, v0.KindMandate, s.mandates, name)
}

// Agent returns an agent by name; x.ErrNotFound when there is none.
func (s *Snapshot) Agent(name string) (Agent, error) {
	return byName(s, v0.KindAgent, s.agents, name)
}

// byName looks a document up by name, failing closed when this version of
// doorward could not read it.
func byName[T any](s *Snapshot, kind string, docs map[string]T, name string) (T, error) {
	var zero T
	if err := s.broken[kind+"/"+name]; err != nil {
		return zero, err
	}
	d, ok := docs[name]
	if !ok {
		return zero, x.ErrNotFound
	}
	return d, nil
}

// brokenFor finds a broken manifest by its audience, which only the raw
// document knows; broken keys for manifests are stored by audience too.
func (s *Snapshot) brokenFor(kind, key string) error {
	return s.broken[kind+"/"+key]
}
