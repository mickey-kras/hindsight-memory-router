#!/usr/bin/env bash
set -euo pipefail

: "${VERSION:?missing release version}"
: "${SOURCE_IMAGE:?missing tested image}"
: "${IMAGE_GHCR:?missing GHCR repository}"
: "${IMAGE_DOCKERHUB:?missing Docker Hub repository}"

[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]

local_config="$(docker image inspect "$SOURCE_IMAGE" --format '{{.Id}}')"
revision="$(docker image inspect "$SOURCE_IMAGE" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')"
test "$revision" = "$GITHUB_SHA"

tags=("$IMAGE_GHCR:$VERSION" "$IMAGE_GHCR:$GITHUB_SHA" "$IMAGE_DOCKERHUB:$VERSION" "$IMAGE_DOCKERHUB:$GITHUB_SHA")
missing=()
for tag in "${tags[@]}"; do
  if docker manifest inspect "$tag" > "$RUNNER_TEMP/release-manifest.json" 2> "$RUNNER_TEMP/release-manifest.err"; then
    remote_config="$(jq -er '.config.digest' "$RUNNER_TEMP/release-manifest.json")"
    if [[ "$remote_config" != "$local_config" ]]; then
      echo "Refusing to replace an existing image: $tag" >&2
      exit 1
    fi
  elif ! grep -Eq 'manifest unknown|no such manifest|manifest (.* )?not found' "$RUNNER_TEMP/release-manifest.err"; then
    cat "$RUNNER_TEMP/release-manifest.err" >&2
    exit 1
  else
    missing+=("$tag")
  fi
done

for tag in "${missing[@]}"; do
  docker tag "$SOURCE_IMAGE" "$tag"
  docker push "$tag"
done

ghcr_digest="$(docker buildx imagetools inspect "$IMAGE_GHCR:$VERSION" --format '{{json .Manifest.Digest}}' | jq -er .)"
dockerhub_digest="$(docker buildx imagetools inspect "$IMAGE_DOCKERHUB:$VERSION" --format '{{json .Manifest.Digest}}' | jq -er .)"
[[ "$ghcr_digest" =~ ^sha256:[a-f0-9]{64}$ ]]
test "$ghcr_digest" = "$dockerhub_digest"
{
  echo 'published=true'
  echo "ghcr_digest=$ghcr_digest"
  echo "dockerhub_digest=$dockerhub_digest"
} >> "$GITHUB_OUTPUT"
