# Contributing

## Sign-off

Every commit carries a `Signed-off-by:` trailer that matches its author,
certifying the [Developer Certificate of Origin](DCO):

```sh
git commit -s
```

CI checks every commit of a pull request (`scripts/check-dco.sh`). To sign
off commits you have already made:

```sh
git rebase --signoff origin/main
```

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
4. a case in `TestInvalidDocuments` for each rule the change adds, showing
   that a document breaking the rule is rejected.

Within v0, a change must keep accepting every document the previous v0
accepted: it may add an optional field or an enum member. Removing a field,
making one required, or narrowing a pattern or an enum is a new version.
