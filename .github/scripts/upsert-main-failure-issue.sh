#!/usr/bin/env bash
set -euo pipefail

: "${FAILURE_KEY:?FAILURE_KEY is required}"
: "${FAILURE_TITLE:?FAILURE_TITLE is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"

body_file="${1:?body file is required}"
marker="<!-- main-failure:${FAILURE_KEY} -->"
payload="$(mktemp)"
trap 'rm -f "$payload"' EXIT

{
  echo "$marker"
  cat "$body_file"
} > "$payload"

issues="$(gh issue list --state all --limit 1000 --json number,title,body,state)"
number="$(
  jq -r --arg marker "$marker" '
    [.[] | select((.body // "") | contains($marker))]
    | sort_by(.number)
    | last
    | .number // empty
  ' <<<"$issues"
)"

if [ -z "$number" ] && [ -n "${LEGACY_TITLE:-}" ]; then
  number="$(
    jq -r --arg title "$LEGACY_TITLE" '
      [.[] | select(.title == $title)]
      | sort_by(.number)
      | last
      | .number // empty
    ' <<<"$issues"
  )"
fi

if [ -n "$number" ]; then
  state="$(jq -r --argjson number "$number" '.[] | select(.number == $number) | .state' <<<"$issues")"
  if [ "$state" = "CLOSED" ] || [ "$state" = "closed" ]; then
    gh issue reopen "$number"
  fi
  gh issue edit "$number" \
    --title "$FAILURE_TITLE" \
    --body-file "$payload" \
    --add-assignee "$GITHUB_REPOSITORY_OWNER"
else
  gh issue create \
    --title "$FAILURE_TITLE" \
    --body-file "$payload" \
    --assignee "$GITHUB_REPOSITORY_OWNER"
fi
