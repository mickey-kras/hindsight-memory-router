"""Normalize a Trivy CycloneDX SBOM into a reproducible release asset."""

import json
import os
import sys
import uuid


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: normalize-sbom.py INPUT OUTPUT")
    subject = os.environ["SBOM_SUBJECT"]
    timestamp = os.environ["SBOM_TIMESTAMP"]
    with open(sys.argv[1], encoding="utf-8") as handle:
        document = json.load(handle)
    if document.get("bomFormat") != "CycloneDX":
        raise SystemExit("expected a CycloneDX SBOM")
    # Trivy stamps wall-clock time and a random serial number. Derive both from
    # the commit and pushed image digest so release retries upload identical
    # bytes and the immutable release asset digest check keeps passing.
    document.setdefault("metadata", {})["timestamp"] = timestamp
    serial = uuid.uuid5(uuid.NAMESPACE_URL, f"{subject}#cyclonedx-sbom")
    document["serialNumber"] = f"urn:uuid:{serial}"
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
