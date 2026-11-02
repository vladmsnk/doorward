package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	v0 "github.com/vladmsnk/doorward/api/v0"
	"github.com/vladmsnk/doorward/internal/configuration"
	"github.com/vladmsnk/doorward/internal/mcp"
	"github.com/vladmsnk/doorward/internal/x"
	"github.com/vladmsnk/doorward/schema"
)

const importUsage = `usage:
  doorward import mcp [flags] URL     draft a manifest from an MCP server's tools
`

// exitChanged is import's exit code when --against was given and the
// server's tools no longer match the manifest.
const exitChanged = 3

func runImport(args []string, stdout, stderr io.Writer) int {
	return dispatch("import", importUsage, args, stderr, map[string]func([]string) int{
		"mcp": func(a []string) int { return runImportMCP(a, stdout, stderr) },
	})
}

// runImportMCP drafts a manifest from what an MCP server's tools/list
// says. It only prints: the draft is applied by a person, through the
// Admin API, once they have checked every tier.
func runImportMCP(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "name of the manifest")
	audience := fs.String("audience", "", "the gateway's address for the server, as grants name it")
	secretRef := fs.String("secret-ref", "", "the stored secret the gateway sends the server as Authorization: Bearer (edit the draft for another header)")
	against := fs.String("against", "", "the manifest as it stands: keep its tiers, name, audience and upstream, and list what changed")
	out := fs.String("o", "", "write the draft to this file instead of stdout")
	mandate := fs.String("mandate", "", "also write a starter mandate for the drafted operations to this file")
	timeout := fs.Duration("timeout", 30*time.Second, "how long to wait for the server")
	header := headerFlag{}
	fs.Var(header, "header", "a header to send the server, such as its credential: 'Authorization: Bearer KEY'; repeatable, never written to the draft")
	var skip listFlag
	fs.Var(&skip, "skip", "leave this tool out of the draft; repeatable")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: doorward import mcp [flags] URL\n\nDrafts a manifest from the tools the MCP server at URL lists, and prints it.\nWith --against, URL defaults to the manifest's upstream and the exit code is\n3 when the server's tools no longer match it.")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	fail := func(code int, format string, a ...any) int {
		fmt.Fprintf(stderr, "doorward import mcp: "+format+"\n", a...)
		return code
	}
	v, err := schema.NewValidator()
	if err != nil {
		return fail(1, "%v", err)
	}

	var base v0.Manifest
	url := fs.Arg(0)
	switch {
	case fs.NArg() > 1:
		fs.Usage()
		return 2
	case *against != "":
		if *name != "" || *audience != "" || *secretRef != "" {
			return fail(2, "--name, --audience and --secret-ref come from the --against manifest")
		}
		if base, err = readManifest(v, *against); err != nil {
			return fail(1, "%v", err)
		}
		if base.Spec.Protocol != v0.ProtocolMCP {
			return fail(2, "manifest %s is an HTTP manifest; only MCP servers list their tools", base.Metadata.Name)
		}
		if url == "" {
			url = base.Spec.Upstream.URL
		}
	default:
		if url == "" || *name == "" || *audience == "" {
			fs.Usage()
			return 2
		}
		if !x.NameRE.MatchString(*name) {
			return fail(2, "--name %q is not a name: lower case letters, digits, '.', '_' and '-'", *name)
		}
		base = v0.Manifest{
			TypeMeta: v0.TypeMeta{APIVersion: v0.APIVersion, Kind: v0.KindManifest},
			Metadata: v0.ObjectMeta{Name: *name},
			Spec:     v0.ManifestSpec{Audience: *audience, Protocol: v0.ProtocolMCP, Upstream: v0.Upstream{URL: url}},
		}
		if *secretRef != "" {
			base.Spec.Upstream.Auth = &v0.UpstreamAuth{Header: "Authorization", Prefix: "Bearer ", SecretRef: *secretRef}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	listing, err := mcp.ListTools(ctx, url, http.Header(header))
	if err != nil {
		if se := (*mcp.StatusError)(nil); errors.As(err, &se) && se.Unauthorized() {
			return fail(1, "%v\nthe server wants a credential: give it with --header", err)
		}
		return fail(1, "%v", err)
	}
	from := listing.Server.Name
	if from == "" {
		from = url
	} else if listing.Server.Version != "" {
		from += " " + listing.Server.Version
	}
	if *against == "" {
		base.Metadata.Description = fmt.Sprintf("Drafted by doorward import from the tools of %s (MCP %s). The tiers come from the server's own hints, so check each one.", from, listing.Server.Protocol)
	}
	d := configuration.DraftManifest(base, listing.Tools, skip)

	if err := check(v, schema.Manifest, d.Manifest); err != nil {
		return fail(1, "the draft is not a valid manifest: %v", err)
	}
	doc, err := toYAML(d.Manifest, "")
	if err != nil {
		return fail(1, "%v", err)
	}
	if err := writeOut(*out, stdout, doc); err != nil {
		return fail(1, "%v", err)
	}
	if *mandate != "" {
		if err := writeStarter(v, *mandate, d.Manifest); err != nil {
			return fail(1, "%v", err)
		}
	}

	fmt.Fprintf(stderr, "%s from %s (MCP %s): %d tools listed, %d operations\n",
		d.Manifest.Metadata.Name, from, listing.Server.Protocol, len(listing.Tools), len(d.Manifest.Spec.Operations))
	if *against != "" && len(d.Changes) == 0 {
		fmt.Fprintln(stderr, "no changes: the server's tools match the manifest")
	}
	for _, c := range d.Changes {
		switch c.Kind {
		case configuration.ChangeAdded:
			fmt.Fprintf(stderr, "+ %s (%s)\n", c.Operation, c.Detail)
		case configuration.ChangeRemoved:
			fmt.Fprintf(stderr, "- %s\n", c.Operation)
		default:
			fmt.Fprintf(stderr, "~ %s: %s\n", c.Operation, c.Detail)
		}
	}
	for _, n := range d.Notes {
		if n.Tool == "" {
			fmt.Fprintf(stderr, "note: %s\n", n.Message)
			continue
		}
		fmt.Fprintf(stderr, "note: %s: %s\n", n.Tool, n.Message)
	}
	if *against != "" && len(d.Changes) > 0 {
		return exitChanged
	}
	return 0
}

// readManifest reads one manifest document from a file, as validate does.
func readManifest(v *schema.Validator, file string) (v0.Manifest, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- reading the file the user named is the command's job
	if err != nil {
		return v0.Manifest{}, err
	}
	srcs, err := schema.Read(file, data, schema.Manifest)
	if err != nil {
		return v0.Manifest{}, err
	}
	if len(srcs) != 1 {
		return v0.Manifest{}, fmt.Errorf("%s: want one manifest, found %d documents", file, len(srcs))
	}
	m, err := schema.Decode[v0.Manifest](v, srcs[0].JSON)
	if err != nil {
		return v0.Manifest{}, fmt.Errorf("%s: %w", file, err)
	}
	return m, nil
}

// writeStarter writes the starter mandate for m, named like it, with a
// comment that says what it leaves out.
func writeStarter(v *schema.Validator, file string, m v0.Manifest) error {
	md, writes, err := configuration.StarterMandate(m.Metadata.Name, m)
	if err != nil {
		return err
	}
	if err := check(v, schema.Mandate, md); err != nil {
		return fmt.Errorf("the starter mandate is not valid: %w", err)
	}
	paragraphs := []string{fmt.Sprintf("A starter mandate for manifest %s: an agent acting for a user may run "+
		"its read operations, and each critical call once the user approves it. "+
		"Write consent.text in words the user understands.", m.Metadata.Name)}
	if len(writes) > 0 {
		paragraphs = append(paragraphs, fmt.Sprintf("Write operations run on a standing grant without asking, so these are "+
			"left out: %s. Add the ones the agent needs; a mandate cannot "+
			"make a write ask first yet (C10).", strings.Join(writes, ", ")))
	}
	doc, err := toYAML(md, comment(paragraphs))
	if err != nil {
		return err
	}
	return os.WriteFile(file, doc, 0o600)
}

// comment writes paragraphs as a YAML comment, wrapped at 76 columns.
func comment(paragraphs []string) string {
	var lines []string
	for i, p := range paragraphs {
		if i > 0 {
			lines = append(lines, "#")
		}
		line := "#"
		for _, word := range strings.Fields(p) {
			if len(line)+1+len(word) > 76 && line != "#" {
				lines = append(lines, line)
				line = "#"
			}
			line += " " + word
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// check validates a document against the contract.
func check(v *schema.Validator, kind schema.Kind, doc any) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return v.Check(kind, data)
}

func writeOut(file string, stdout io.Writer, data []byte) error {
	if file == "" {
		_, err := stdout.Write(data)
		return err
	}
	return os.WriteFile(file, data, 0o600)
}

// toYAML writes a document as YAML in the field order of its JSON, the
// examples' layout: each param, and each list of names, on one line.
// comment, when set, goes above it.
func toYAML(doc any, comment string) ([]byte, error) {
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		return nil, err
	}
	layout(&n, "")
	n.HeadComment = comment
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// layout drops the JSON styles a node decoded from JSON carries, then puts
// short values on one line: params, lists of names, approvers. key is the
// mapping key the node is the value of.
func layout(n *yaml.Node, key string) {
	n.Style = 0
	switch {
	case n.Kind == yaml.SequenceNode && (key == "actions" || key == "groups"):
		n.Style = yaml.FlowStyle
	case n.Kind == yaml.MappingNode && key == "approvers":
		n.Style = yaml.FlowStyle
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			layout(k, "")
			layout(val, k.Value)
			if key == "params" && val.Kind == yaml.MappingNode {
				val.Style = yaml.FlowStyle
			}
		}
		return
	}
	for _, c := range n.Content {
		layout(c, "")
	}
}

// headerFlag collects --header "Name: value".
type headerFlag http.Header

func (h headerFlag) String() string { return "" }

func (h headerFlag) Set(s string) error {
	name, value, ok := strings.Cut(s, ":")
	name = strings.TrimSpace(name)
	if !ok || name == "" || strings.ContainsAny(name, " \t") {
		return errors.New(`want "Name: value"`)
	}
	http.Header(h).Add(name, strings.TrimSpace(value))
	return nil
}

// listFlag collects a flag given more than once.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}
