"""Check that public distributions contain source files, not local state or secrets."""

import argparse
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SDIST_ROOTS = {
    ".gitignore",
    ".gitattributes",
    "src",
    "tests",
    "scripts",
    "examples",
    "README.md",
    "CONTRIBUTING.md",
    "CHANGELOG.md",
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "config.example.json",
    "pyproject.toml",
    "requirements.lock",
    "uv.lock",
    "PKG-INFO",
}
FORBIDDEN_PARTS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
    "config.local.json",
}


def check_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"Invalid archive path: {name}")
    for part in path.parts:
        if (
            part in FORBIDDEN_PARTS
            or part.startswith((".venv", ".kali-mcp", ".env"))
            or (part.startswith("config.") and part.endswith(".local.json"))
            or part.endswith((".pyc", ".pyo", ".log", ".pcap", ".pcapng", ".pem", ".key"))
            or ".sqlite3" in part
            or part.endswith((".db", ".db-wal", ".db-shm"))
        ):
            raise ValueError(f"Local or generated file in archive: {name}")
    return path


def check_distributions(directory: Path) -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    stem = project["name"].replace("-", "_") + "-" + project["version"]
    wheel = directory / f"{stem}-py3-none-any.whl"
    sdist = directory / f"{stem}.tar.gz"
    archives = set(directory.glob("*.whl")) | set(directory.glob("*.tar.gz"))
    if archives != {wheel, sdist}:
        raise ValueError(f"Expected only {wheel.name} and {sdist.name} in {directory}")

    dist_info = f"{stem}.dist-info"
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        for name in names:
            if check_path(name).parts[0] not in {"kali_mcp", dist_info}:
                raise ValueError(f"Unexpected wheel file: {name}")
        required = {
            f"{dist_info}/METADATA",
            f"{dist_info}/entry_points.txt",
            "kali_mcp/__init__.py",
            "kali_mcp/__main__.py",
        }
        required |= {
            p.relative_to(ROOT / "src").as_posix()
            for p in (ROOT / "src" / "kali_mcp").rglob("*.py")
        }
        if missing := required - names:
            raise ValueError(f"Missing wheel files: {sorted(missing)}")
        print(f"OK {wheel.name}: {len(names)} entries")

    with tarfile.open(sdist, "r:gz") as archive:
        names = set()
        for member in archive.getmembers():
            path = check_path(member.name)
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"Non-regular sdist entry: {member.name}")
            if path.parts[0] != stem:
                raise ValueError(f"Unexpected sdist root: {member.name}")
            if len(path.parts) > 1 and path.parts[1] not in SDIST_ROOTS:
                raise ValueError(f"Unexpected sdist file: {member.name}")
            names.add(path.relative_to(stem).as_posix())
        required = {"README.md", "pyproject.toml", "config.example.json", "PKG-INFO"}
        if missing := required - names:
            raise ValueError(f"Missing sdist files: {sorted(missing)}")
        print(f"OK {sdist.name}: {len(names)} entries")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    try:
        check_distributions(args.directory)
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError) as error:
        parser.exit(1, f"Distribution check failed: {error}\n")


if __name__ == "__main__":
    main()
