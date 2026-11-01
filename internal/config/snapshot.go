// Package config keeps a decision point's copy of the configuration: every
// enabled manifest by audience, every mandate and agent by name, decoded
// once per change rather than once per call.
package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/store"
	"github.com/vladmsnk/doorward/schema"
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

// Mandate returns a mandate by name; store.ErrNotFound when there is none.
func (s *Snapshot) Mandate(name string) (Mandate, error) {
	if err := s.broken[v0.KindMandate+"/"+name]; err != nil {
		return Mandate{}, err
	}
	m, ok := s.mandates[name]
	if !ok {
		return Mandate{}, store.ErrNotFound
	}
	return m, nil
}

// Agent returns an agent by name; store.ErrNotFound when there is none.
func (s *Snapshot) Agent(name string) (Agent, error) {
	if err := s.broken[v0.KindAgent+"/"+name]; err != nil {
		return Agent{}, err
	}
	a, ok := s.agents[name]
	if !ok {
		return Agent{}, store.ErrNotFound
	}
	return a, nil
}

// brokenFor finds a broken manifest by its audience, which only the raw
// document knows; broken keys for manifests are stored by audience too.
func (s *Snapshot) brokenFor(kind, key string) error {
	return s.broken[kind+"/"+key]
}

// Cache serves snapshots, reloading when the store's configuration version
// changes.
type Cache struct {
	Store     store.Store
	Validator *schema.Validator
	Log       *slog.Logger

	mu   sync.Mutex
	snap *Snapshot
}

// Current returns the snapshot for the store's current configuration
// version: the cached one when nothing changed, a fresh one otherwise. One
// query per call in the common case.
func (c *Cache) Current(ctx context.Context) (*Snapshot, error) {
	version, err := c.Store.ConfigVersion(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snap != nil && c.snap.Version == version {
		return c.snap, nil
	}
	snap, err := c.load(ctx, version)
	if err != nil {
		return nil, err
	}
	c.snap = snap
	return snap, nil
}

// Invalidate drops the cached snapshot; the next Current reloads.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	c.snap = nil
	c.mu.Unlock()
}

// load reads every document. The version was read before the documents,
// so a write that lands in between shows as a newer version next time
// and the snapshot is reloaded then.
func (c *Cache) load(ctx context.Context, version uint64) (*Snapshot, error) {
	snap := &Snapshot{Version: version, manifests: map[string]Manifest{}, mandates: map[string]Mandate{}, agents: map[string]Agent{}, broken: map[string]error{}}
	docs := c.Store.Documents()
	manifests, err := docs.List(ctx, v0.KindManifest)
	if err != nil {
		return nil, err
	}
	for _, d := range manifests {
		if d.Disabled {
			continue
		}
		m, err := schema.Decode[v0.Manifest](c.Validator, d.Doc)
		if err != nil {
			c.markBroken(snap, d, audienceOf(d.Doc), err)
			continue
		}
		snap.manifests[m.Spec.Audience] = Manifest{Manifest: m, Digest: d.Digest}
	}
	mandates, err := docs.List(ctx, v0.KindMandate)
	if err != nil {
		return nil, err
	}
	for _, d := range mandates {
		m, err := schema.Decode[v0.Mandate](c.Validator, d.Doc)
		if err != nil {
			c.markBroken(snap, d, d.Name, err)
			continue
		}
		snap.mandates[d.Name] = Mandate{Mandate: m, Digest: d.Digest, Disabled: d.Disabled}
	}
	agents, err := docs.List(ctx, v0.KindAgent)
	if err != nil {
		return nil, err
	}
	for _, d := range agents {
		a, err := schema.Decode[v0.Agent](c.Validator, d.Doc)
		if err != nil {
			c.markBroken(snap, d, d.Name, err)
			continue
		}
		snap.agents[d.Name] = Agent{Agent: a, Digest: d.Digest}
	}
	return snap, nil
}

func (c *Cache) markBroken(snap *Snapshot, d store.Document, key string, err error) {
	wrapped := fmt.Errorf("%w: %s %s version %d: %w", ErrBroken, d.Kind, d.Name, d.Version, err)
	snap.broken[d.Kind+"/"+key] = wrapped
	if c.Log != nil {
		c.Log.Error("configuration document cannot be read by this version; calls under it are refused",
			"kind", d.Kind, "name", d.Name, "version", d.Version, "err", err)
	}
}

// audienceOf reads a manifest's audience without decoding the rest, so a
// manifest this version cannot read is still known by the location it
// serves.
func audienceOf(doc []byte) string {
	var m struct {
		Spec struct {
			Audience string `json:"audience"`
		} `json:"spec"`
	}
	_ = json.Unmarshal(doc, &m)
	return m.Spec.Audience
}
