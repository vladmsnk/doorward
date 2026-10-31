# Working on agentbox with Claude Code

## Commits: a person authors and signs off, never Claude

- Never author, commit or sign off a commit as Claude or any other AI
  identity: no `Claude <noreply@anthropic.com>` as author or committer, and
  no `Signed-off-by:` naming an AI. A sign-off certifies the Developer
  Certificate of Origin, which only a person can do.
- Commit as the maintainer: `vladmsnk <73408532+vladmsnk@users.noreply.github.com>`.
  Before the first commit of a session, check `git config user.name` and
  `git config user.email` in this clone; if they name Claude, set them to
  the maintainer's identity. If someone else is driving the session, ask
  whose identity to use instead of guessing.
- Sign off with `git commit -s`, under that identity.
- Disclose the assistance openly with a `Co-Authored-By:` trailer naming
  the assistant. This is allowed and expected; it is not a sign-off.
- Run `make hooks` once per clone. The commit-msg hook refuses a commit
  that breaks these rules before it exists; `scripts/check-dco.sh` refuses
  it in CI on every pull request and every push to main.

## Before pushing

`make ci`. For the store tests, point `AGENTBOX_TEST_POSTGRES_DSN` at an
empty PostgreSQL database (`make test-db` starts one).

## The plan

Work follows [docs/ROADMAP.md](docs/ROADMAP.md), one step per pull request,
each with its tests and a "how to validate" section.
