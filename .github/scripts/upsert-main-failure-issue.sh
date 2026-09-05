#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  exec node .github/scripts/report-main-failures.cjs
fi

: "${FAILURE_KEY:?FAILURE_KEY is required}"
: "${FAILURE_TITLE:?FAILURE_TITLE is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"

body_file="${1:?body file is required}"
marker="<!-- main-failure:${FAILURE_KEY} -->"
: "${FAILURE_OCCURRENCE:?FAILURE_OCCURRENCE is required}"
occurrence="<!-- main-occurrence:${FAILURE_OCCURRENCE} -->"
payload="$(mktemp)"
trap 'rm -f "$payload"' EXIT

{
  echo "$marker"
  echo "$occurrence"
  cat "$body_file"
} > "$payload"

issues="$(gh issue list --state all --limit 2147483647 --json number,title,body,state)"

number="$(
  jq -r --arg marker "$marker" '
    [.[] | select((.body // "") | contains($marker))]
    | sort_by(.number)
    | last
    | .number // empty
  ' <<<"$issues"
)"

if [ -n "$number" ]; then
  state="$(jq -r --argjson number "$number" '.[] | select(.number == $number) | .state' <<<"$issues")"
  existing_body="$(jq -r --argjson number "$number" '.[] | select(.number == $number) | .body // ""' <<<"$issues")"
  comments="$(gh api "/repos/${GITHUB_REPOSITORY}/issues/${number}/comments?per_page=100" --paginate --slurp | jq -r 'add | .[].body')"
  if ! printf '%s\n%s\n' "$existing_body" "$comments" | grep -F "$occurrence" > /dev/null; then
    if [ "$state" = "CLOSED" ] || [ "$state" = "closed" ]; then
      gh issue reopen "$number"
    fi
    gh issue comment "$number" --body-file "$payload"
  fi
else
  gh issue create \
    --title "$FAILURE_TITLE" \
    --body-file "$payload" \
    --assignee "$GITHUB_REPOSITORY_OWNER"
fi
