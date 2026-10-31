package v0_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	v0 "github.com/vladmsnk/agentbox/api/v0"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCanonicalNumbers(t *testing.T) {
	// From RFC 8785 Appendix B, and the ECMAScript boundaries.
	cases := map[float64]string{
		0:                        "0",
		math.Copysign(0, -1):     "0",
		1:                        "1",
		-1:                       "-1",
		4.5:                      "4.5",
		0.002:                    "0.002",
		0.000001:                 "0.000001",
		0.0000001:                "1e-7",
		1e21:                     "1e+21",
		1e20:                     "100000000000000000000",
		1e30:                     "1e+30",
		333333333.33333329:       "333333333.3333333",
		9007199254740992:         "9007199254740992",
		295147905179352830000:    "295147905179352830000",
		4.94065645841246544e-324: "5e-324",
		1.7976931348623157e308:   "1.7976931348623157e+308",
		-1.5e-7:                  "-1.5e-7",
		123.456:                  "123.456",
		7500:                     "7500",
		240.5:                    "240.5",
	}
	for f, want := range cases {
		got, err := v0.Canonical(f)
		if err != nil || string(got) != want {
			t.Errorf("%v: got %s %v, want %s", f, got, err, want)
		}
	}
	for _, bad := range []float64{math.NaN(), math.Inf(1)} {
		if _, err := v0.Canonical(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestCanonicalRFCExample(t *testing.T) {
	// RFC 8785 §3.2.2: the example input and its canonical output.
	in := `{
	  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
	  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
	  "literals": [null, true, false]
	}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := v0.Canonical(decode(t, in))
	if err != nil || string(got) != want {
		t.Errorf("got  %s %v\nwant %s", got, err, want)
	}
}

func TestCanonicalKeyOrder(t *testing.T) {
	// RFC 8785 §3.2.3: members sort by UTF-16 code units, so the emoji
	// (a surrogate pair, 0xD83D...) comes before U+FB33.
	in := `{"€":"Euro Sign","\r":"Carriage Return","דּ":"Hebrew Letter Dalet With Dagesh","1":"One","😀":"Emoji: Grinning Face","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis"}`
	got, err := v0.Canonical(decode(t, in))
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	dec := json.NewDecoder(strings.NewReader(string(got)))
	_, _ = dec.Token()
	for dec.More() {
		k, _ := dec.Token()
		order = append(order, k.(string))
		var skip any
		_ = dec.Decode(&skip)
	}
	want := []string{"\r", "1", "\u0080", "ö", "€", "\U0001F600", "דּ"}
	if strings.Join(order, "|") != strings.Join(want, "|") {
		t.Errorf("order %q, want %q", order, want)
	}
}

func TestActionHash(t *testing.T) {
	a := v0.ApprovedAction{Name: "pay_invoice", Location: "https://payments.example.internal",
		Arguments: map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 1200.0, "currency": "EUR"}}
	h1, err := a.Hash()
	if err != nil || !strings.HasPrefix(h1, "sha-256:") || len(h1) != 8+43 {
		t.Fatalf("%q %v", h1, err)
	}
	// The same call written another way hashes the same.
	b := v0.ApprovedAction{Name: "pay_invoice", Location: "https://payments.example.internal",
		Arguments: decode(t, `{ "currency" : "EUR", "amount": 1.2e3, "invoice_id": "inv_7Q2M9X4K" }`).(map[string]any)}
	if h2, _ := b.Hash(); h2 != h1 {
		t.Errorf("same call, different hash: %s %s", h1, h2)
	}
	// Any change is a different call.
	for _, change := range []func(*v0.ApprovedAction){
		func(x *v0.ApprovedAction) {
			x.Arguments = map[string]any{"invoice_id": "inv_7Q2M9X4K", "amount": 1200.01, "currency": "EUR"}
		},
		func(x *v0.ApprovedAction) { x.Name = "refund_payment" },
		func(x *v0.ApprovedAction) { x.Location = "https://payments.example.internal/" },
	} {
		c := a
		change(&c)
		if h, _ := c.Hash(); h == h1 {
			t.Errorf("changed call, same hash: %+v", c)
		}
	}
	// No arguments and empty arguments are the same call.
	n1, _ := v0.ApprovedAction{Name: "x", Location: "https://a"}.Hash()
	n2, _ := v0.ApprovedAction{Name: "x", Location: "https://a", Arguments: map[string]any{}}.Hash()
	if n1 != n2 {
		t.Error("nil and empty arguments hash differently")
	}
}
