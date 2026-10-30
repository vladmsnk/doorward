#!/usr/bin/env bash
# Fails unless every non-merge commit in BASE..HEAD carries a
# "Signed-off-by:" trailer that matches the commit's author (see DCO and
# CONTRIBUTING.md). CI runs it on every pull request; run it locally with
# `make dco-check`.
#
# usage: scripts/check-dco.sh BASE [HEAD]
set -euo pipefail

base=${1:?usage: check-dco.sh BASE [HEAD]}
head=${2:-HEAD}

status=0
count=0
while read -r sha; do
	count=$((count + 1))
	author="$(git show -s --format='%an <%ae>' "$sha")"
	if ! git show -s --format='%(trailers:key=Signed-off-by,valueonly)' "$sha" | grep -qxF "$author"; then
		echo "commit $(git show -s --format='%h %s' "$sha")" >&2
		echo "  has no trailer: Signed-off-by: $author" >&2
		status=1
	fi
done < <(git rev-list --no-merges "$base..$head")

if [ "$status" -ne 0 ]; then
	echo >&2
	echo "Sign off with 'git commit -s'; fix existing commits with 'git rebase --signoff $base'." >&2
	exit "$status"
fi
echo "DCO: $count commit(s) signed off"
