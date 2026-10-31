package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source is one document read from a file and turned into JSON.
type Source struct {
	// Name is the file name, with "#n" appended for the n-th document of a
	// multi-document YAML file.
	Name string
	Kind Kind
	JSON []byte
}

// Read splits a file into its documents and converts each to JSON. Files
// ending in .yaml or .yml may hold several documents separated by "---";
// anything else is read as a single JSON document.
//
// kind, when not empty, is the kind every document must be. When it is empty
// each document's kind comes from its kind field, which only configuration
// documents carry; messages and records need kind set.
func Read(name string, data []byte, kind Kind) ([]Source, error) {
	var docs [][]byte
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml":
		var err error
		if docs, err = yamlToJSON(data); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	default:
		docs = [][]byte{data}
	}

	out := make([]Source, 0, len(docs))
	for i, doc := range docs {
		src := Source{Name: name, JSON: doc}
		if len(docs) > 1 {
			src.Name = name + "#" + strconv.Itoa(i+1)
		}
		k, err := kindOfDocument(doc, kind)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		src.Kind = k
		out = append(out, src)
	}
	return out, nil
}

// kindOfDocument resolves the kind of one document against the kind the
// caller expects, if any.
func kindOfDocument(doc []byte, want Kind) (Kind, error) {
	var head struct {
		Kind *string `json:"kind"`
	}
	// A document that is not a JSON object fails validation later with a
	// better message; here it simply has no kind field.
	_ = json.Unmarshal(doc, &head)

	if head.Kind == nil {
		if want == "" {
			return "", errors.New("document has no kind field; give the kind explicitly for messages and records such as grants")
		}
		return want, nil
	}
	got, err := ParseKind(*head.Kind)
	if err != nil || !got.Enveloped() || string(got) != *head.Kind {
		var config []string
		for _, k := range Kinds {
			if k.Enveloped() {
				config = append(config, string(k))
			}
		}
		return "", fmt.Errorf("kind %q is not a configuration kind (%s)", *head.Kind, strings.Join(config, ", "))
	}
	if want != "" && got != want {
		return "", fmt.Errorf("document is a %s, expected a %s", got, want)
	}
	return got, nil
}

// yamlToJSON converts each document of a YAML stream to JSON. yaml.v3 refuses
// a mapping that repeats a key, which is the same guarantee CheckDuplicateKeys
// gives for JSON input. Empty documents are skipped.
func yamlToJSON(data []byte) ([][]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var out [][]byte
	for n := 1; ; n++ {
		var doc any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		if doc == nil {
			continue
		}
		plain, err := jsonCompatible(doc, "")
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		js, err := json.Marshal(plain)
		if err != nil {
			return nil, fmt.Errorf("document %d: %w", n, err)
		}
		out = append(out, js)
	}
	if len(out) == 0 {
		return nil, errors.New("no documents")
	}
	return out, nil
}

// jsonCompatible rewrites a decoded YAML value so that encoding/json accepts
// it: every mapping key must be a string, since JSON has no other kind.
func jsonCompatible(v any, at string) (any, error) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			c, err := jsonCompatible(val, at+"/"+k)
			if err != nil {
				return nil, err
			}
			t[k] = c
		}
		return t, nil
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("at %q: mapping key %v is not a string", at, k)
			}
			c, err := jsonCompatible(val, at+"/"+ks)
			if err != nil {
				return nil, err
			}
			m[ks] = c
		}
		return m, nil
	case []any:
		for i, val := range t {
			c, err := jsonCompatible(val, at+"/"+strconv.Itoa(i))
			if err != nil {
				return nil, err
			}
			t[i] = c
		}
		return t, nil
	default:
		return v, nil
	}
}

// CheckDuplicateKeys rejects a JSON text in which any object repeats a member
// name, and a text with anything after its value. encoding/json keeps the
// last of two duplicate members and other parsers keep the first; two
// components reading one grant or one policy differently is how a forged
// field gets past a check.
func CheckDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSON(dec, ""); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func walkJSON(dec *json.Decoder, at string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	switch tok {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("parse JSON: %w", err)
			}
			key, ok := kt.(string)
			if !ok {
				return fmt.Errorf("parse JSON: object key at %q is not a string", at)
			}
			if seen[key] {
				return fmt.Errorf("duplicate key %q at %q", key, at)
			}
			seen[key] = true
			if err := walkJSON(dec, at+"/"+escapePointer(key)); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	case json.Delim('['):
		for i := 0; dec.More(); i++ {
			if err := walkJSON(dec, at+"/"+strconv.Itoa(i)); err != nil {
				return err
			}
		}
		_, err = dec.Token()
	}
	if err != nil {
		return fmt.Errorf("parse JSON: %w", err)
	}
	return nil
}

// escapePointer escapes a member name for a JSON Pointer (RFC 6901 §3).
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
