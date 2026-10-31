#!/usr/bin/env bash
# Checks the commits in BASE..HEAD (see DCO and CONTRIBUTING.md):
#
#  - every non-merge commit carries a "Signed-off-by:" trailer that matches
#    its author;
#  - no commit, merges included, is authored, committed or signed off by an
#    AI assistant, or names one as co-author or carries a Claude-Session
#    trailer. A sign-off certifies the Developer Certificate of Origin,
#    which only a person can do, and the person who signs off is the
#    contributor. The README states that development is AI-assisted.
#
# CI runs it on every pull request and every push to main; run it locally
# with `make dco-check`.
#
# usage: scripts/check-dco.sh BASE [HEAD]
#        BASE may be empty to check every commit reachable from HEAD.
set -euo pipefail

base=${1?usage: check-dco.sh BASE [HEAD]}
head=${2:-HEAD}
range="$head"
if [ -n "$base" ]; then
	range="$base..$head"
fi

# Identities that are not a person who can certify the DCO.
not_a_person='@anthropic\.com>?$|^Claude([ <]|$)'

status=0
count=0
while read -r sha; do
	count=$((count + 1))
	what="$(git show -s --format='%h %s' "$sha")"
	author="$(git show -s --format='%an <%ae>' "$sha")"
	committer="$(git show -s --format='%cn <%ce>' "$sha")"
	signoffs="$(git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha")"
	if grep -qE "$not_a_person" <<<"$author"; then
		echo "commit $what" >&2
		echo "  is authored by an AI assistant ($author); author it as the person submitting it" >&2
		status=1
	fi
	if grep -qE "$not_a_person" <<<"$committer"; then
		echo "commit $what" >&2
		echo "  is committed by an AI assistant ($committer)" >&2
		status=1
	fi
	if grep -E "$not_a_person" <<<"$signoffs" | grep -q .; then
		echo "commit $what" >&2
		echo "  is signed off by an AI assistant; only a person can certify the DCO" >&2
		status=1
	fi
	coauthors="$(git show -s --format='%(trailers:key=Co-authored-by,valueonly)' "$sha")"
	if grep -E "$not_a_person" <<<"$coauthors" | grep -q .; then
		echo "commit $what" >&2
		echo "  names an AI assistant as co-author; the README states the assistance, commits do not" >&2
		status=1
	fi
	if git show -s --format='%B' "$sha" | grep -qi '^Claude-Session:'; then
		echo "commit $what" >&2
		echo "  carries a Claude-Session trailer" >&2
		status=1
	fi
	if [ "$(git rev-list --no-walk --count --min-parents=2 "$sha")" = 0 ] && ! grep -qxF "$author" <<<"$signoffs"; then
		echo "commit $what" >&2
		echo "  has no trailer: Signed-off-by: $author" >&2
		status=1
	fi
done < <(git rev-list "$range")

if [ "$status" -ne 0 ]; then
	echo >&2
	echo "Commit as yourself and sign off with 'git commit -s'; see CONTRIBUTING.md." >&2
	exit "$status"
fi
echo "DCO: $count commit(s) authored and signed off by a person, with no AI attribution"
