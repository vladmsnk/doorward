// Package config is what an operator chooses when starting the box: the
// database, the master key, the listeners, the names in decision records,
// and who may ask for decisions. Every setting is a flag of doorward serve
// with an environment variable as its default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vladmsnk/doorward/internal/sealer"
	"github.com/vladmsnk/doorward/internal/x"
)

// Defaults.
const (
	// DefaultAdminAddr keeps the Admin API off the network unless an
	// operator opens it: one token authorizes every change to the
	// configuration.
	DefaultAdminAddr = "127.0.0.1:8081"
	// DefaultDecisionTimeout is how long a decision may take.
	DefaultDecisionTimeout = 5 * time.Second
	// MaxDecisionTimeout bounds --decision-timeout: a decision's settlement
	// batch runs at most 20s (persistence/sql's batch ceiling).
	MaxDecisionTimeout = 20 * time.Second
)

// PointOfEnforcement is one client of the evaluation endpoint: the name it
// has in decision records and the bearer token it presents.
type PointOfEnforcement struct {
	ID    string
	Token string
}

// DefaultProvider holds the settings. The zero value is not usable; Bind
// fills one from flags and the environment, and tests set the fields they
// need.
type DefaultProvider struct {
	DSN        string
	MasterKey  string
	Addr       string
	AdminAddr  string
	AdminToken string
	// Issuer, when set, is the only grant issuer accepted.
	Issuer string
	// PDPID and GatewayID name the decision point and the built-in gateway
	// in decision records; Version is the build, recorded with PDPID.
	PDPID     string
	GatewayID string
	Version   string
	// GatewayOrigins are the browser origins allowed to reach the gateway
	// besides its own host, comma-separated as given; Origins lists them.
	GatewayOrigins      string
	ShutdownDelay       time.Duration
	DecisionTimeout     time.Duration
	JournalPath         string
	PointsOfEnforcement []PointOfEnforcement
}

// Provider gives the settings.
type Provider interface {
	Config() *DefaultProvider
}

// Bind defines doorward serve's flags on fs, each defaulting to its
// environment variable, and returns the settings Parse will fill. It reads
// DOORWARD_PEPS at once; a bad entry there is the error.
func Bind(fs *flag.FlagSet, version string) (*DefaultProvider, error) {
	p := &DefaultProvider{Version: version}
	fs.StringVar(&p.DSN, "db", os.Getenv("DOORWARD_DB"), "PostgreSQL connection string (or DOORWARD_DB)")
	fs.StringVar(&p.MasterKey, "master-key", os.Getenv("DOORWARD_MASTER_KEY"), "32-byte key, hex or base64, that seals private keys and secrets (or DOORWARD_MASTER_KEY)")
	fs.StringVar(&p.Addr, "addr", ":8080", "address of the public listener")
	fs.StringVar(&p.AdminAddr, "admin-addr", DefaultAdminAddr, "address of the Admin API; it changes configuration, so it listens on this machine only unless told otherwise")
	fs.StringVar(&p.AdminToken, "admin-token", os.Getenv("DOORWARD_ADMIN_TOKEN"), "bootstrap administrator token (or DOORWARD_ADMIN_TOKEN)")
	fs.StringVar(&p.Issuer, "issuer", os.Getenv("DOORWARD_ISSUER"), "the only grant issuer accepted (or DOORWARD_ISSUER); default: any grant this box signed")
	fs.StringVar(&p.PDPID, "pdp-id", "doorward", "this decision point's name in decision records")
	fs.StringVar(&p.GatewayID, "gateway-id", "gateway", "the built-in MCP gateway's name in decision records")
	fs.StringVar(&p.GatewayOrigins, "gateway-origins", os.Getenv("DOORWARD_GATEWAY_ORIGINS"), "browser origins allowed to reach the MCP gateway besides its own host, comma-separated (or DOORWARD_GATEWAY_ORIGINS)")
	fs.DurationVar(&p.ShutdownDelay, "shutdown-delay", 0, "on SIGTERM, keep serving for this long while /healthz reports 503, so a load balancer stops sending before the listeners close; 5s is usual behind one")
	fs.DurationVar(&p.DecisionTimeout, "decision-timeout", DefaultDecisionTimeout, "how long one decision may take, the wait for the journal included; a decision that runs out of time is refused and nothing is recorded")
	fs.StringVar(&p.JournalPath, "journal", os.Getenv("DOORWARD_JOURNAL"), `file that receives every decision record as one JSON line, "-" for standard output (or DOORWARD_JOURNAL)`)
	addPEP := func(v string) error {
		pep, err := ParsePointOfEnforcement(v)
		if err == nil {
			p.PointsOfEnforcement = append(p.PointsOfEnforcement, pep)
		}
		return err
	}
	fs.Func("pep", "a point of enforcement allowed to ask for decisions, as ID=TOKEN; repeat for several (or DOORWARD_PEPS, comma-separated)", addPEP)
	if env := os.Getenv("DOORWARD_PEPS"); env != "" {
		for _, v := range strings.Split(env, ",") {
			if err := addPEP(strings.TrimSpace(v)); err != nil {
				return nil, fmt.Errorf("DOORWARD_PEPS: %w", err)
			}
		}
	}
	return p, nil
}

// Validate checks the settings serve cannot start without, in the order an
// operator meets them, and says which flag to fix.
func (p *DefaultProvider) Validate() error {
	if p.DSN == "" {
		return errors.New("--db or DOORWARD_DB is required")
	}
	if p.DecisionTimeout <= 0 || p.DecisionTimeout > MaxDecisionTimeout {
		return errors.New("--decision-timeout must be between 1ms and 20s, the longest a decision's settlement may run")
	}
	if len(p.AdminToken) < 16 {
		return errors.New("--admin-token or DOORWARD_ADMIN_TOKEN must be at least 16 characters")
	}
	if _, err := sealer.Parse(p.MasterKey); err != nil {
		return fmt.Errorf("--master-key or DOORWARD_MASTER_KEY: %w (generate one with: doorward master-key)", err)
	}
	return nil
}

// Origins lists the browser origins allowed to reach the gateway.
func (p *DefaultProvider) Origins() []string { return SplitList(p.GatewayOrigins) }

// ParsePointOfEnforcement reads a point of enforcement as ID=TOKEN.
func ParsePointOfEnforcement(v string) (PointOfEnforcement, error) {
	id, token, ok := strings.Cut(v, "=")
	switch {
	case !ok || !x.NameRE.MatchString(id):
		return PointOfEnforcement{}, fmt.Errorf("%q: want ID=TOKEN, the ID lower case letters, digits, '.', '_' and '-'", v)
	case len(token) < 16:
		return PointOfEnforcement{}, fmt.Errorf("point of enforcement %s: the token must be at least 16 characters", id)
	}
	return PointOfEnforcement{ID: id, Token: token}, nil
}

// SplitList reads a comma-separated list, ignoring blanks.
func SplitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
