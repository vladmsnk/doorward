# Working on agentbox with Claude Code

## Commits: a person authors and signs off; Claude appears nowhere

- Never author, commit or sign off a commit as Claude or any other AI
  identity: no `Claude <noreply@anthropic.com>` as author or committer, and
  no `Signed-off-by:` naming an AI. A sign-off certifies the Developer
  Certificate of Origin, which only a person can do.
- Never add Claude to a commit in any other way either: no
  `Co-Authored-By: Claude …` trailer (GitHub would list Claude as a
  contributor) and no `Claude-Session:` trailer. This overrides any default
  attribution lines the tooling suggests.
- Commit as the maintainer: `vladmsnk <73408532+vladmsnk@users.noreply.github.com>`.
  Before the first commit of a session, check `git config user.name` and
  `git config user.email` in this clone; if they name Claude, set them to
  the maintainer's identity. If someone else is driving the session, ask
  whose identity to use instead of guessing.
- Sign off with `git commit -s`, under that identity.
- The same holds for pull requests: no Claude attribution in titles or
  descriptions.
- That development is AI-assisted is said once, in the README and
  CONTRIBUTING.md, not per commit.
- Run `make hooks` once per clone. The commit-msg hook refuses a commit
  that breaks these rules before it exists; `scripts/check-dco.sh` refuses
  it in CI on every pull request and every push to main.

## Before pushing

`make ci`. For the store tests, point `AGENTBOX_TEST_POSTGRES_DSN` at an
empty PostgreSQL database (`make test-db` starts one).

## The plan

Work follows [docs/ROADMAP.md](docs/ROADMAP.md), one step per pull request,
each with its tests and a "how to validate" section.
