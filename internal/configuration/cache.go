package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/schema"
)

// Cache serves snapshots, reloading when the store's configuration version
// changes.
type Cache struct {
	Store     Source
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

func (c *Cache) markBroken(snap *Snapshot, d Document, key string, err error) {
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
