// Package schema embeds the v0 JSON Schemas and validates documents against
// them.
//
// Every document the box accepts — configuration a company writes, a grant
// presented at a point of enforcement, a record read back as evidence — goes
// through the same four steps: duplicate member
// names are rejected, the document is validated against its schema, it is
// decoded strictly into its Go type from package api/v0, and the type's own
// Check enforces the rules that span fields.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	v0 "github.com/vladmsnk/agentbox/api/v0"
)

//go:embed v0/*.schema.json
var files embed.FS

// BaseURL is the base of every v0 schema's $id. The schemas are embedded;
// nothing is fetched from it.
const BaseURL = "https://agentbox.dev/schema/v0/"

// Kind names a v0 document kind.
type Kind string

const (
	Manifest Kind = v0.KindManifest
	Agent    Kind = v0.KindAgent
	Mandate  Kind = v0.KindMandate
	Consent  Kind = "Consent"
	Grant    Kind = "Grant"
	Decision Kind = "Decision"
	Approval Kind = "Approval"
)

// Kinds lists every kind: configuration first, then records in the order an
// agent's work produces them.
var Kinds = []Kind{Manifest, Agent, Mandate, Consent, Grant, Decision, Approval}

// ParseKind accepts a kind name in any letter case, so "grant" and
// "tasktype" work on the command line.
func ParseKind(s string) (Kind, error) {
	for _, k := range Kinds {
		if strings.EqualFold(s, string(k)) {
			return k, nil
		}
	}
	names := make([]string, len(Kinds))
	for i, k := range Kinds {
		names[i] = string(k)
	}
	return "", fmt.Errorf("unknown kind %q (want one of %s)", s, strings.Join(names, ", "))
}

// Enveloped reports whether documents of the kind carry apiVersion, kind and
// metadata. Only configuration does: the other kinds are records the box
// produces, and the grant follows a standard's shape.
func (k Kind) Enveloped() bool {
	return k == Manifest || k == Agent || k == Mandate
}

// File is the name of the kind's schema file.
func (k Kind) File() string { return strings.ToLower(string(k)) + ".schema.json" }

// URL is the $id of the kind's schema.
func (k Kind) URL() string { return BaseURL + k.File() }

// Files returns the embedded schema files, keyed by file name.
func Files() map[string][]byte {
	out := make(map[string][]byte)
	entries, err := fs.ReadDir(files, "v0")
	if err != nil {
		panic(err) // the directory is embedded at build time
	}
	for _, e := range entries {
		data, err := files.ReadFile(path.Join("v0", e.Name()))
		if err != nil {
			panic(err)
		}
		out[e.Name()] = data
	}
	return out
}

// Validator holds the compiled schemas. It is safe for concurrent use.
type Validator struct {
	schemas map[Kind]*jsonschema.Schema
}

// NewValidator compiles the embedded schemas, with format assertions on:
// a "uri" or "date-time" that is not one is an error, not an annotation.
func NewValidator() (*Validator, error) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for name, data := range Files() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parse schema %s: %w", name, err)
		}
		if err := c.AddResource(BaseURL+name, doc); err != nil {
			return nil, fmt.Errorf("add schema %s: %w", name, err)
		}
	}
	v := &Validator{schemas: make(map[Kind]*jsonschema.Schema, len(Kinds))}
	for _, k := range Kinds {
		s, err := c.Compile(k.URL())
		if err != nil {
			return nil, fmt.Errorf("compile schema %s: %w", k.File(), err)
		}
		v.schemas[k] = s
	}
	return v, nil
}

// Validate checks one JSON document against the schema of kind.
func (v *Validator) Validate(kind Kind, doc []byte) error {
	s, ok := v.schemas[kind]
	if !ok {
		return fmt.Errorf("unknown kind %q", kind)
	}
	if err := CheckDuplicateKeys(doc); err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return fmt.Errorf("parse document: %w", err)
	}
	return s.Validate(inst)
}

// Document is any of the v0 document types.
type Document interface {
	v0.Manifest | v0.Agent | v0.Mandate | v0.Consent | v0.Grant | v0.Decision | v0.Approval
}

// KindOf returns the kind of a document type.
func KindOf[T Document]() Kind {
	var zero T
	switch any(zero).(type) {
	case v0.Manifest:
		return Manifest
	case v0.Agent:
		return Agent
	case v0.Mandate:
		return Mandate
	case v0.Consent:
		return Consent
	case v0.Grant:
		return Grant
	case v0.Decision:
		return Decision
	default:
		return Approval
	}
}

// RuleError reports a document that has the right shape but breaks a rule
// spanning its fields.
type RuleError struct {
	Kind Kind
	Err  error
}

func (e *RuleError) Error() string { return e.Err.Error() }

func (e *RuleError) Unwrap() error { return e.Err }

// Check validates a JSON document of the given kind completely: schema,
// strict decoding and the rules that span fields.
func (v *Validator) Check(kind Kind, doc []byte) error {
	var err error
	switch kind {
	case Manifest:
		_, err = Decode[v0.Manifest](v, doc)
	case Agent:
		_, err = Decode[v0.Agent](v, doc)
	case Mandate:
		_, err = Decode[v0.Mandate](v, doc)
	case Consent:
		_, err = Decode[v0.Consent](v, doc)
	case Grant:
		_, err = Decode[v0.Grant](v, doc)
	case Decision:
		_, err = Decode[v0.Decision](v, doc)
	case Approval:
		_, err = Decode[v0.Approval](v, doc)
	default:
		err = fmt.Errorf("unknown kind %q", kind)
	}
	return err
}

// Decode validates a JSON document, decodes it into its Go type and runs the
// type's Check. Fields the type does not know are an error even if the schema
// let them through, so a drift between the two cannot pass silently.
func Decode[T Document](v *Validator, doc []byte) (T, error) {
	var out T
	if err := v.Validate(KindOf[T](), doc); err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("decode %s: %w", KindOf[T](), err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return out, errors.New("trailing data after the document")
	}
	if c, ok := any(out).(interface{ Check() error }); ok {
		if err := c.Check(); err != nil {
			return out, &RuleError{Kind: KindOf[T](), Err: err}
		}
	}
	return out, nil
}
