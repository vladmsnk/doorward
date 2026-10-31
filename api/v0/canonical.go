package v0

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonical writes decoded JSON in the JSON Canonicalization Scheme
// (RFC 8785): object members sorted by their UTF-16 code units, no
// whitespace, strings escaped minimally, numbers as ECMAScript prints them.
// Two parties that decode the same JSON value get the same bytes, whatever
// order or spacing the original had.
//
// v holds what encoding/json decodes into an any: map[string]any, []any,
// string, float64, bool and nil. json.Number is accepted too.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := canon(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func canon(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return canonString(b, x)
	case float64:
		s, err := canonNumber(x)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return fmt.Errorf("number %s: %w", x, err)
		}
		return canon(b, f)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canon(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := canonString(b, k); err != nil {
				return err
			}
			b.WriteByte(':')
			if err := canon(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON: unsupported type %T", v)
	}
	return nil
}

// canonString escapes only what JSON requires (RFC 8785 §3.2.2.2).
func canonString(b *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("canonical JSON: string is not valid UTF-8")
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return nil
}

// canonNumber prints a number as ECMAScript's Number.prototype.toString
// does (RFC 8785 §3.2.2.3): the shortest digits that read back to the same
// double, in plain notation from 1e-6 up to 1e21, in exponent notation
// outside it.
func canonNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("canonical JSON: %v is not a JSON number", f)
	}
	if f == 0 {
		return "0", nil // -0 too
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-trip digits and the decimal exponent: d.ddde±x.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, exp, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, err := strconv.Atoi(exp)
	if err != nil {
		return "", err
	}
	k, n := len(digits), x+1 // n: where the decimal point falls
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		es := "+"
		if n-1 < 0 {
			es = "-"
		}
		abs := n - 1
		if abs < 0 {
			abs = -abs
		}
		s = digits[:1]
		if k > 1 {
			s += "." + digits[1:]
		}
		s += "e" + es + strconv.Itoa(abs)
	}
	return sign + s, nil
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 sorts
// member names.
func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// Hash is the action hash of a call: the digest of its canonical form. An
// approval is bound to it, a single-use grant is issued for it, and the
// decision record names it, so all three refer to exactly one call. Absent
// arguments hash as an empty object.
func (a ApprovedAction) Hash() (string, error) {
	args := a.Arguments
	if args == nil {
		args = map[string]any{}
	}
	data, err := Canonical(map[string]any{"name": a.Name, "location": a.Location, "arguments": args})
	if err != nil {
		return "", err
	}
	return Digest(data), nil
}

// CanonicalDocument returns a JSON document in canonical form (RFC 8785)
// and its digest. The box stores configuration in this form and names each
// version by this digest, so a consent's mandate_version depends on what
// the mandate says, not on how it was formatted when it was sent.
func CanonicalDocument(doc []byte) ([]byte, string, error) {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return nil, "", fmt.Errorf("document is not JSON: %w", err)
	}
	canon, err := Canonical(v)
	if err != nil {
		return nil, "", err
	}
	return canon, Digest(canon), nil
}
