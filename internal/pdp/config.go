package pdp

import (
	"context"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
)

// snapshotConfig lets the grant's status check read agents and mandates
// from the decision point's snapshot instead of the store.
type snapshotConfig struct{ cache *configuration.Cache }

func (c snapshotConfig) Agent(ctx context.Context, name string) (v0.Agent, error) {
	snap, err := c.cache.Current(ctx)
	if err != nil {
		return v0.Agent{}, err
	}
	a, err := snap.Agent(name)
	return a.Agent, err
}

func (c snapshotConfig) Mandate(ctx context.Context, name string) (v0.Mandate, bool, error) {
	snap, err := c.cache.Current(ctx)
	if err != nil {
		return v0.Mandate{}, false, err
	}
	m, err := snap.Mandate(name)
	return m.Mandate, m.Disabled, err
}

// StatusConfig is what a grant.StoreStatus takes as Config to read agents
// and mandates from this cache.
func StatusConfig(c *configuration.Cache) snapshotConfig { return snapshotConfig{c} }
