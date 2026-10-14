import importlib.metadata
import importlib.resources
import os
import sys
import tomllib
from pathlib import Path

source = Path(sys.argv[1])
project = tomllib.loads((source / "pyproject.toml").read_text())
distribution = importlib.metadata.distribution(project["project"]["name"])
assert distribution.version == project["project"]["version"]
resource = importlib.resources.files("memory_router").joinpath("confusables_ascii.json")
assert resource.read_bytes() == (source / "memory_router/confusables_ascii.json").read_bytes()
assert not resource.is_relative_to(source), "package must load from the installed wheel"

files = {str(file): file for file in distribution.files or []}
for license_file in [source / "LICENSE", *sorted((source / "licenses").glob("*.txt"))]:
    matches = [
        file for name, file in files.items() if name.endswith("/licenses/" + license_file.name)
    ]
    assert len(matches) == 1, f"missing packaged license: {license_file.name}"
    assert distribution.locate_file(matches[0]).read_bytes() == license_file.read_bytes()

installed = {
    dist.metadata["Name"].lower().replace("_", "-") for dist in importlib.metadata.distributions()
}
dev = {
    requirement.split("==")[0] for requirement in project["project"]["optional-dependencies"]["dev"]
}
assert not installed & (dev | {"setuptools", "wheel", "build"}), installed
if "--container" in sys.argv:
    assert os.getuid() == 10001, "runtime must use the unprivileged app user"
    assert "pip" not in installed, "runtime must not ship pip"
    assert (Path("/app/THIRD_PARTY_NOTICES.md")).read_bytes() == (
        source / "THIRD_PARTY_NOTICES.md"
    ).read_bytes()
    for license_file in (source / "licenses").glob("*.txt"):
        assert (Path("/app/licenses") / license_file.name).read_bytes() == license_file.read_bytes()

print(f"installed wheel verified: {distribution.metadata['Name']}=={distribution.version}")
