#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

"${script_dir}/smoke.sh" fake 2> >(sed 's/fake/stub/g' >&2) | sed 's/fake/stub/g'
