#!/usr/bin/env bash
set -euo pipefail

# Local keys and a loopback registry exercise the release CLI without OIDC,
# production registries, or public transparency-log entries.
smoke_dir="$(mktemp -d)"
registry_id=''
cleanup() {
  if [ -n "$registry_id" ]; then docker rm --force --volumes "$registry_id" >/dev/null; fi
  rm -rf "$smoke_dir"
}
trap cleanup EXIT
export COSIGN_PASSWORD=''
cosign version
cosign generate-key-pair --output-key-prefix "$smoke_dir/signer"
cosign generate-key-pair --output-key-prefix "$smoke_dir/wrong-signer"

registry_id="$(docker run --detach --publish 127.0.0.1::5000 \
  registry:3.1.2@sha256:ddf754342cfc8acc51a56d5d0ab6af06826461864460636d8bd5c546dab2a7b8)"
registry_address="$(docker port "$registry_id" 5000/tcp)"
for attempt in {1..30}; do
  if curl --fail --silent "http://$registry_address/v2/" >/dev/null; then break; fi
  sleep 1
done
curl --fail --silent "http://$registry_address/v2/" >/dev/null

image="$registry_address/attestation-smoke"
mkdir "$smoke_dir/image"
printf 'FROM scratch\nLABEL purpose=attestation-smoke\n' > "$smoke_dir/image/Dockerfile"
docker build --tag "$image:smoke" "$smoke_dir/image"
docker push "$image:smoke"
subject="$(docker image inspect --format '{{index .RepoDigests 0}}' "$image:smoke")"

cat > "$smoke_dir/provenance.json" <<'JSON'
{
  "buildDefinition": {
    "buildType": "https://actions.github.io/buildtypes/workflow/v1",
    "externalParameters": {"workflow": {"repository": "https://github.com/example/smoke", "ref": "refs/heads/main", "path": ".github/workflows/smoke.yml"}},
    "internalParameters": {},
    "resolvedDependencies": []
  },
  "runDetails": {
    "builder": {"id": "https://github.com/example/smoke/.github/workflows/smoke.yml@refs/heads/main"},
    "metadata": {"invocationId": "https://github.com/example/smoke/actions/runs/1/attempts/1"}
  }
}
JSON
cat > "$smoke_dir/sbom.json" <<'JSON'
{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"application","name":"attestation-smoke","version":"1.0.0"}]}
JSON

for predicate in provenance sbom; do
  if [ "$predicate" = provenance ]; then
    predicate_type='https://slsa.dev/provenance/v1'
  else
    predicate_type='https://cyclonedx.org/bom'
  fi
  # These local-key flags disable public services only in this smoke test.
  cosign attest --yes --predicate "$smoke_dir/$predicate.json" \
    --type "$predicate_type" --bundle "$smoke_dir/$predicate.bundle.json" \
    --key "$smoke_dir/signer.key" --use-signing-config=false --tlog-upload=false \
    --allow-http-registry "$subject"
  cosign verify-attestation --type "$predicate_type" --key "$smoke_dir/signer.pub" \
    --insecure-ignore-tlog --allow-http-registry "$subject" > "$smoke_dir/$predicate.verified.json"

  python3 - "$smoke_dir" "$predicate" "$predicate_type" "$subject" <<'PY'
import base64
import json
import sys
from pathlib import Path

directory, predicate, predicate_type, subject = sys.argv[1:]
root = Path(directory)
bundle = json.loads((root / f"{predicate}.bundle.json").read_text())
assert bundle["mediaType"] == "application/vnd.dev.sigstore.bundle.v0.3+json"
assert bundle["verificationMaterial"]["publicKey"]["hint"]
envelope = bundle["dsseEnvelope"]
assert envelope["payloadType"] == "application/vnd.in-toto+json"
assert len(envelope["signatures"]) == 1 and envelope["signatures"][0]["sig"]
statement = json.loads(base64.b64decode(envelope["payload"], validate=True))
name, digest = subject.split("@sha256:")
assert statement["_type"] == "https://in-toto.io/Statement/v0.1"
assert statement["predicateType"] == predicate_type
assert statement["subject"] == [{"name": name, "digest": {"sha256": digest}}]
assert statement["predicate"] == json.loads((root / f"{predicate}.json").read_text())
verified = json.loads((root / f"{predicate}.verified.json").read_text())
assert verified["payload"] == envelope["payload"], "Registry attestation differs from local bundle"
PY

  if cosign verify-attestation --type "$predicate_type" --key "$smoke_dir/wrong-signer.pub" \
    --insecure-ignore-tlog --allow-http-registry "$subject"; then
    echo 'Attestation verification accepted the wrong signing key' >&2
    exit 1
  fi
done

if cosign verify-attestation --type 'https://example.invalid/missing-predicate' \
  --key "$smoke_dir/signer.pub" --insecure-ignore-tlog --allow-http-registry "$subject"; then
  echo 'Attestation verification accepted the wrong predicate type' >&2
  exit 1
fi
