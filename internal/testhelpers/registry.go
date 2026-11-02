// Package testhelpers builds what the tests of several packages share: a
// registry on the test database, emptied, with its own master key and
// signing key.
package testhelpers

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/vladmsnk/doorward/internal/driver"
	"github.com/vladmsnk/doorward/internal/driver/config"
	"github.com/vladmsnk/doorward/internal/sealer"
)

// AdminToken is the administrator token of every test registry.
const AdminToken = "test-admin-token-0123456789"

// Tables are every table a test empties before it starts.
const Tables = "documents, consents, grants, decisions, approvals, counters, signing_keys, secrets"

// NewRegistry returns an open registry on the database named by
// DOORWARD_TEST_POSTGRES_DSN, skipping the test without one. The database
// is emptied, a fresh master key seals a fresh signing key, logs are
// discarded, and the settings are serve's defaults with AdminToken; edit
// adjusts them, and before runs on the registry before it is opened, for
// the With methods.
func NewRegistry(t testing.TB, edit func(*config.DefaultProvider), before ...func(*driver.RegistryDefault)) *driver.RegistryDefault {
	t.Helper()
	st := OpenPersister(t)
	ctx := context.Background()
	master, err := sealer.Generate()
	if err != nil {
		t.Fatal(err)
	}
	conf := &config.DefaultProvider{
		MasterKey: master, AdminToken: AdminToken,
		PDPID: "doorward", GatewayID: "gateway", Version: "test",
		DecisionTimeout: config.DefaultDecisionTimeout,
	}
	if edit != nil {
		edit(conf)
	}
	reg := driver.New(conf).WithPersister(st).WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, b := range before {
		b(reg)
	}
	if err := reg.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.KeyRing().Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	return reg
}
