# Contributing

## Sign-off

Every commit carries a `Signed-off-by:` trailer that matches its author,
certifying the [Developer Certificate of Origin](DCO):

```sh
git commit -s
```

CI checks every commit of a pull request and of every push to main
(`scripts/check-dco.sh`). `make hooks` installs a commit-msg hook that runs
the same check before a commit is made. To sign off commits you have
already made:

```sh
git rebase --signoff origin/main
```

## AI-assisted development

Much of agentbox is written with an AI coding assistant (Claude Code). The
assistance is disclosed, not hidden:

- Every commit is authored and signed off by the person who submits it,
  who answers for it under the DCO. An AI cannot certify the DCO, so a
  commit authored, committed or signed off by an AI identity is refused.
- Commits carry no AI attribution trailer (`Co-Authored-By:` naming an
  assistant, `Claude-Session:`): the person who signs off is the
  contributor. This section and the README are where the assistance is
  stated.

## Before you push

```sh
make ci
```

It runs what CI runs: `go mod tidy -diff`, gofmt, `go vet`, golangci-lint,
the tests with the race detector, and validation of every example through the
CLI.

## Changing a schema

A schema change is one change across four places, in the same commit:

1. the JSON Schema in `schema/v0`;
2. the Go type in `api/v0`; the drift test fails until the two agree on
   field names, on what is required (required fields are not `omitempty`,
   optional ones are) and on enum members;
3. an example in `examples/v0` that uses the new field, if it is new;
4. a case for each rule the change adds, showing that a document breaking
   it is rejected: in `TestInvalidDocuments` for a rule in the schema, in
   `TestRuleChecks` for a rule in the type's `Check` method.

From the first tagged release on, a v0 change must keep accepting every
document the previous release accepted: it may add an optional field or an
enum member. Removing a field, making one required, or narrowing a pattern
or an enum is a new version. Until that release, v0 is a draft and may still
change in any way.
