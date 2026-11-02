package grant_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/grant"
	"github.com/vladmsnk/doorward/internal/jwk"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

const aud = "https://payments.example.internal"

// fakeKeys is a key table: kid to public key.
type fakeKeys map[string]*ecdsa.PublicKey

func (f fakeKeys) Public(_ context.Context, kid string) (*ecdsa.PublicKey, error) {
	if k, ok := f[kid]; ok {
		return k, nil
	}
	return nil, x.ErrNotFound
}

type brokenKeys struct{}

func (brokenKeys) Public(context.Context, string) (*ecdsa.PublicKey, error) {
	return nil, errors.New("database down")
}

// fakeStatus refuses the grant IDs it lists.
type fakeStatus map[string]string

func (f fakeStatus) Standing(_ context.Context, g v0.Grant) (grant.Standing, error) {
	if f["*"] == "error" {
		return grant.Standing{}, errors.New("database down")
	}
	return grant.Standing{Refusal: f[g.ID], Ceiling: v0.SensitivityCritical}, nil
}

type fixture struct {
	signer *jwk.Signer
	claims v0.Grant
	v      *grant.Verifier
	now    time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	val, err := schema.NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../examples/v0/grant/pay-invoice.json")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := schema.Decode[v0.Grant](val, data)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(claims.IssuedAt, 0).Add(5 * time.Minute)
	f := &fixture{
		signer: &jwk.Signer{KID: "kid-1", Private: priv},
		claims: claims,
		now:    now,
	}
	f.v = &grant.Verifier{
		Keys:      fakeKeys{"kid-1": &priv.PublicKey},
		Status:    fakeStatus{},
		Validator: val,
		Issuer:    claims.Issuer,
		Now:       func() time.Time { return f.now },
	}
	return f
}

func (f *fixture) sign(t *testing.T, g v0.Grant) string {
	t.Helper()
	tok, err := grant.Sign(f.signer, g)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// signRaw signs any header and payload, so a test can build a token the box
// would never write but whose signature is genuine.
func signRaw(t *testing.T, priv *ecdsa.PrivateKey, header, payload string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	input := enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString([]byte(payload))
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig)
}

func (f *fixture) payload(t *testing.T, edit func(m map[string]any)) string {
	t.Helper()
	raw, _ := json.Marshal(f.claims)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if edit != nil {
		edit(m)
	}
	out, _ := json.Marshal(m)
	return string(out)
}

const goodHeader = `{"alg":"ES256","typ":"at+jwt","kid":"kid-1"}`

func checks(r grant.Result) string {
	var b strings.Builder
	for _, c := range r.Checks {
		b.WriteString(string(c.Name) + ":" + string(c.Result) + " ")
	}
	return strings.TrimSpace(b.String())
}

func TestValidGrant(t *testing.T) {
	f := setup(t)
	r, err := f.v.Verify(context.Background(), f.sign(t, f.claims), aud)
	if err != nil || !r.OK() {
		t.Fatalf("refused: %+v %v", r.Reason, err)
	}
	if got := checks(r); got != "signature:pass status:pass pop:skip audience:pass time:pass" {
		t.Errorf("checks: %s", got)
	}
	if r.Standing == nil || r.Standing.Ceiling != v0.SensitivityCritical {
		t.Errorf("standing: %+v", r.Standing)
	}
	if r.Grant.ID != f.claims.ID || r.Grant.Subject != "alice@example.com" {
		t.Errorf("grant: %+v", r.Grant)
	}
	// Both typ spellings RFC 9068 allows are accepted.
	tok := signRaw(t, f.signer.Private, `{"alg":"ES256","typ":"application/AT+JWT","kid":"kid-1"}`, f.payload(t, nil))
	if r, _ := f.v.Verify(context.Background(), tok, aud); !r.OK() {
		t.Errorf("media-type typ refused: %+v", r.Reason)
	}
}

func TestRefusals(t *testing.T) {
	f := setup(t)
	good := f.sign(t, f.claims)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	parts := strings.Split(good, ".")
	enc := base64.RawURLEncoding

	tamperedPayload := parts[0] + "." + enc.EncodeToString([]byte(strings.Replace(f.payload(t, nil), "5000", "50000", 1))) + "." + parts[2]
	sig, _ := enc.DecodeString(parts[2])
	sig[10] ^= 1

	cases := []struct {
		name  string
		tok   string
		aud   string
		check v0.CheckName
		code  v0.ReasonCode
	}{
		{"empty", "", aud, v0.CheckSignature, v0.ReasonGrantMissing},
		{"not a jws", "abc.def", aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"padding", parts[0] + "=." + parts[1] + "." + parts[2], aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"too large", strings.Repeat("a", grant.MaxTokenSize+1), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"alg none", signRaw(t, f.signer.Private, `{"alg":"none","typ":"at+jwt","kid":"kid-1"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"alg HS256", signRaw(t, f.signer.Private, `{"alg":"HS256","typ":"at+jwt","kid":"kid-1"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"id token typ", signRaw(t, f.signer.Private, `{"alg":"ES256","typ":"JWT","kid":"kid-1"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"no kid", signRaw(t, f.signer.Private, `{"alg":"ES256","typ":"at+jwt"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"crit header", signRaw(t, f.signer.Private, `{"alg":"ES256","typ":"at+jwt","kid":"kid-1","crit":["x"]}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"embedded jwk", signRaw(t, other, `{"alg":"ES256","typ":"at+jwt","kid":"kid-1","jwk":{}}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"duplicate header member", signRaw(t, f.signer.Private, `{"alg":"ES256","alg":"ES256","typ":"at+jwt","kid":"kid-1"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"unknown kid", signRaw(t, f.signer.Private, `{"alg":"ES256","typ":"at+jwt","kid":"kid-9"}`, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantSignatureInvalid},
		{"other key", signRaw(t, other, goodHeader, f.payload(t, nil)), aud, v0.CheckSignature, v0.ReasonGrantSignatureInvalid},
		{"tampered payload", tamperedPayload, aud, v0.CheckSignature, v0.ReasonGrantSignatureInvalid},
		{"tampered signature", parts[0] + "." + parts[1] + "." + enc.EncodeToString(sig), aud, v0.CheckSignature, v0.ReasonGrantSignatureInvalid},
		{"short signature", parts[0] + "." + parts[1] + "." + enc.EncodeToString(sig[:63]), aud, v0.CheckSignature, v0.ReasonGrantSignatureInvalid},
		// Signed by the box's own key, but not a valid grant.
		{"missing claim", signRaw(t, f.signer.Private, goodHeader, f.payload(t, func(m map[string]any) { delete(m, "mandate") })), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"unknown claim", signRaw(t, f.signer.Private, goodHeader, f.payload(t, func(m map[string]any) { m["scope"] = "admin" })), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"rule broken", signRaw(t, f.signer.Private, goodHeader, f.payload(t, func(m map[string]any) { delete(m, "consent") })), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"duplicate claim", signRaw(t, f.signer.Private, goodHeader, strings.Replace(f.payload(t, nil), `"sub":"alice@example.com"`, `"sub":"alice@example.com","sub":"bob@example.com"`, 1)), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"other issuer", f.sign(t, func() v0.Grant { g := f.claims; g.Issuer = "https://evil.example"; return g }()), aud, v0.CheckSignature, v0.ReasonGrantMalformed},
		{"other audience", good, "https://ledger.example.internal", v0.CheckAudience, v0.ReasonAudienceMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := f.v.Verify(context.Background(), c.tok, c.aud)
			if err != nil {
				t.Fatal(err)
			}
			if r.OK() {
				t.Fatal("accepted")
			}
			last := r.Checks[len(r.Checks)-1]
			if last.Name != c.check || last.Result != v0.CheckFail || r.Reason.Code != c.code {
				t.Errorf("got %s/%s %s (%s), want %s failing with %s", last.Name, last.Result, r.Reason.Code, r.Reason.Message, c.check, c.code)
			}
			if c.check == v0.CheckSignature && r.Grant != nil {
				t.Error("claims exposed from a token that failed its signature check")
			}
		})
	}
}

func TestStatus(t *testing.T) {
	f := setup(t)
	tok := f.sign(t, f.claims)
	f.v.Status = fakeStatus{f.claims.ID: "agent invoice-assistant is suspended"}
	r, err := f.v.Verify(context.Background(), tok, aud)
	if err != nil || r.OK() || r.Reason.Code != v0.ReasonGrantRevoked || checks(r) != "signature:pass status:fail" {
		t.Fatalf("revoked grant: %s %+v %v", checks(r), r.Reason, err)
	}
	if r.Reason.Message != "agent invoice-assistant is suspended" {
		t.Errorf("message: %q", r.Reason.Message)
	}
}

func TestTime(t *testing.T) {
	f := setup(t)
	tok := f.sign(t, f.claims)
	iat, exp := time.Unix(f.claims.IssuedAt, 0), time.Unix(f.claims.Expiry, 0)
	cases := []struct {
		at   time.Time
		code v0.ReasonCode // empty: accepted
	}{
		{iat, ""},
		{iat.Add(-20 * time.Second), ""}, // within the skew
		{iat.Add(-time.Minute), v0.ReasonGrantNotYetValid},
		{exp.Add(-time.Second), ""},
		{exp.Add(29 * time.Second), ""}, // within the skew
		{exp.Add(30 * time.Second), v0.ReasonGrantExpired},
	}
	for _, c := range cases {
		f.now = c.at
		r, err := f.v.Verify(context.Background(), tok, aud)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case c.code == "" && !r.OK():
			t.Errorf("at %s: refused with %+v", c.at.UTC(), r.Reason)
		case c.code != "" && (r.OK() || r.Reason.Code != c.code):
			t.Errorf("at %s: want %s, got %s %+v", c.at.UTC(), c.code, checks(r), r.Reason)
		}
	}
}

func TestRetiredKeyStillVerifies(t *testing.T) {
	// A grant signed before a rotation stays good until it expires: the
	// verifier finds keys by kid, published or not.
	f := setup(t)
	tok := f.sign(t, f.claims)
	newer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.v.Keys = fakeKeys{"kid-1": &f.signer.Private.PublicKey, "kid-2": &newer.PublicKey}
	if r, _ := f.v.Verify(context.Background(), tok, aud); !r.OK() {
		t.Fatalf("refused: %+v", r.Reason)
	}
}

func TestNoAudienceIsSkipped(t *testing.T) {
	f := setup(t)
	r, _ := f.v.Verify(context.Background(), f.sign(t, f.claims), "")
	if !r.OK() || checks(r) != "signature:pass status:pass pop:skip audience:skip time:pass" {
		t.Fatalf("%s %+v", checks(r), r.Reason)
	}
}

func TestDependencyFailures(t *testing.T) {
	f := setup(t)
	tok := f.sign(t, f.claims)

	f.v.Keys = brokenKeys{}
	r, err := f.v.Verify(context.Background(), tok, aud)
	if err == nil || r.OK() || r.Reason.Code != v0.ReasonInternalError {
		t.Errorf("key table down: %+v %v", r.Reason, err)
	}

	f = setup(t)
	f.v.Status = fakeStatus{"*": "error"}
	r, err = f.v.Verify(context.Background(), f.sign(t, f.claims), aud)
	if err == nil || r.OK() || r.Reason.Code != v0.ReasonInternalError || checks(r) != "signature:pass status:fail" {
		t.Errorf("status down: %s %+v %v", checks(r), r.Reason, err)
	}
}

func TestSignedTokenShape(t *testing.T) {
	f := setup(t)
	tok := f.sign(t, f.claims)
	h, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	if string(h) != goodHeader {
		t.Errorf("header %s", h)
	}
}

// BenchmarkVerify measures a grant's checks without the database: parsing,
// the ES256 signature, the schema and the grant's rules.
func BenchmarkVerify(b *testing.B) {
	t := &testing.T{}
	f := setup(t)
	tok, err := grant.Sign(f.signer, f.claims)
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if r, _ := f.v.Verify(ctx, tok, aud); !r.OK() {
			b.Fatal(r.Reason)
		}
	}
}

// P6: a grant that claims a key binding the box does not check fails pop,
// instead of being honoured as a Bearer token.
func TestBoundGrantFailsPoP(t *testing.T) {
	f := setup(t)
	g := f.claims
	g.Confirmation = &v0.Confirmation_{JKT: strings.Repeat("k", 43)}
	r, err := f.v.Verify(context.Background(), f.sign(t, g), aud)
	if err != nil || r.OK() || r.Reason.Code != v0.ReasonPoPMissing || checks(r) != "signature:pass status:pass pop:fail" {
		t.Fatalf("%s %+v %v", checks(r), r.Reason, err)
	}
}
