"""Read-only parsers for installed environments and lockfiles.

Every parser returns a list of ``(ecosystem, name, version, direct)`` tuples, where
``direct`` is ``"direct"``, ``"transitive"`` or ``"unknown"``.

Rules shared by all parsers:

* Nothing is imported, executed or installed. Only metadata text and lockfiles are read.
* Only packages that come from the public registry (PyPI or npmjs) are returned. Workspace
  members, local paths, git checkouts and private indexes are skipped, because sending
  those names to a public advisory API would disclose internal package names.
* Malformed input returns what could be parsed, never raises.
"""

import glob
import json
import os
import pathlib
import re
import sys
import tomllib
from shutil import which

MAX_LOCKFILE_BYTES = 50 * 1024 * 1024
PUBLIC_PYPI_HOSTS = ("pypi.org", "files.pythonhosted.org", "pypi.python.org")


def _read_text(path):
    try:
        if path.stat().st_size > MAX_LOCKFILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _requirement_name(spec):
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec or "")
    return match.group(1) if match else None


def _pep503(name):
    return re.sub(r"[-_.]+", "-", name).lower()


# --------------------------------------------------------------------------- Python


def _metadata_name_version(text):
    name = re.search(r"^Name:\s*(.+)$", text, re.M | re.I)
    version = re.search(r"^Version:\s*(.+)$", text, re.M | re.I)
    if name and version:
        return name.group(1).strip(), version.group(1).strip()
    return None


def site_packages_records(directory):
    """Read ``*.dist-info/METADATA`` and ``*.egg-info`` (file or folder) in one directory."""
    records, seen = [], set()
    try:
        entries = list(pathlib.Path(directory).iterdir())
    except OSError:
        return records
    for entry in entries:
        if entry.name.endswith(".dist-info"):
            meta = entry / "METADATA"
        elif entry.name.endswith(".egg-info"):
            meta = entry / "PKG-INFO" if entry.is_dir() else entry
        else:
            continue
        text = _read_text(meta)
        parsed = _metadata_name_version(text[:25000]) if text else None
        if not parsed:
            continue
        key = (_pep503(parsed[0]), parsed[1])
        if key not in seen:
            seen.add(key)
            records.append(("PyPI", parsed[0], parsed[1], "unknown"))
    return records


def site_packages_dirs(env):
    """site-packages folders of a venv or conda env on POSIX (lib/pythonX.Y) or Windows (Lib)."""
    env = pathlib.Path(env)
    found = []
    windows = env / "Lib" / "site-packages"
    if windows.is_dir():
        found.append(windows)
    lib = env / "lib"
    try:
        for child in lib.iterdir() if lib.is_dir() else ():
            if child.name.startswith("python") and (child / "site-packages").is_dir():
                found.append(child / "site-packages")
    except OSError:
        pass
    return found


def python_env(env):
    records, seen = [], set()
    for directory in site_packages_dirs(env):
        for record in site_packages_records(directory):
            key = (_pep503(record[1]), record[2])
            if key not in seen:
                seen.add(key)
                records.append(record)
    return records


def _pyproject_declared(project):
    """Names a project declares directly (PEP 621, Poetry and dependency groups)."""
    text = _read_text(pathlib.Path(project) / "pyproject.toml")
    if not text:
        return set()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return set()
    names = set()
    proj = data.get("project", {})
    specs = list(proj.get("dependencies", []))
    for group in (proj.get("optional-dependencies") or {}).values():
        specs.extend(group)
    for group in (data.get("dependency-groups") or {}).values():
        specs.extend(x for x in group if isinstance(x, str))
    for spec in specs:
        name = _requirement_name(spec)
        if name:
            names.add(_pep503(name))
    poetry = data.get("tool", {}).get("poetry", {})
    tables = [poetry.get("dependencies", {}), poetry.get("dev-dependencies", {})]
    tables += [g.get("dependencies", {}) for g in (poetry.get("group") or {}).values()]
    for table in tables:
        names.update(_pep503(n) for n in table if n.lower() != "python")
    return names


def _direct_flag(name, declared):
    if not declared:
        return "unknown"
    return "direct" if _pep503(name) in declared else "transitive"


def poetry_lock(project):
    text = _read_text(pathlib.Path(project) / "poetry.lock")
    try:
        data = tomllib.loads(text) if text else {}
    except tomllib.TOMLDecodeError:
        return []
    declared = _pyproject_declared(project)
    out = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        # No [package.source] means the default index (PyPI). Any explicit source is a
        # path, git URL or private index: skip it rather than leak its name.
        if pkg.get("source"):
            continue
        out.append(("PyPI", name, version, _direct_flag(name, declared)))
    return out


def uv_lock(project):
    text = _read_text(pathlib.Path(project) / "uv.lock")
    try:
        data = tomllib.loads(text) if text else {}
    except tomllib.TOMLDecodeError:
        return []
    declared = _pyproject_declared(project)
    out = []
    for pkg in data.get("package", []):
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source") or {}
        registry = source.get("registry", "") if isinstance(source, dict) else ""
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        if not any(host in registry for host in PUBLIC_PYPI_HOSTS):
            continue  # editable, virtual, path, git or private registry
        out.append(("PyPI", name, version, _direct_flag(name, declared)))
    return out


def pipfile_lock(project):
    text = _read_text(pathlib.Path(project) / "Pipfile.lock")
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    sources = (data.get("_meta") or {}).get("sources") or []
    public = {
        s.get("name")
        for s in sources
        if isinstance(s, dict) and any(h in str(s.get("url", "")) for h in PUBLIC_PYPI_HOSTS)
    } or {"pypi"}
    out = []
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version", ""))
            if not version.startswith("==") or info.get("index", "pypi") not in public:
                continue  # path, git, editable or private index
            out.append(("PyPI", name, version[2:], "unknown"))
    return out


# ------------------------------------------------------------------------------ npm


def _package_json_declared(project):
    try:
        data = json.loads((pathlib.Path(project) / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    names = set()
    if isinstance(data, dict):
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            if isinstance(data.get(section), dict):
                names.update(data[section])
    return names


def npm_lock(project):
    project = pathlib.Path(project)
    declared = _package_json_declared(project)
    text = _read_text(project / "package-lock.json")
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    out = []
    if isinstance(data.get("packages"), dict):
        for key, info in data["packages"].items():
            if not key or not isinstance(info, dict) or not info.get("version"):
                continue
            # Keys without node_modules/ are workspace members or local folders
            # (e.g. "packages/app"); they are not public registry packages.
            if "node_modules/" not in key or info.get("link"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[-1]
            if not name or name.startswith("../") or (name.startswith("@") and "/" not in name):
                continue
            top_level = key.startswith("node_modules/") and key.count("node_modules/") == 1
            if not declared:
                direct = "unknown"
            else:
                direct = "direct" if top_level and name in declared else "transitive"
            out.append(("npm", name, str(info["version"]), direct))
    else:  # lockfile v1: nested "dependencies" objects

        def walk(deps):
            if not isinstance(deps, dict):
                return
            for name, info in deps.items():
                if not isinstance(info, dict):
                    continue
                version = str(info.get("version", ""))
                if version and not version.startswith(("file:", "git", "http", "link:")):
                    out.append(("npm", name, version, "unknown"))
                walk(info.get("dependencies", {}))

        walk(data.get("dependencies", {}))
    return out


def _split_spec(spec):
    """'@scope/name@range' -> ('@scope/name', 'range').

    Splits on the first '@' after the optional scope '@', so aliases such as
    'alias@npm:real@^1' yield ('alias', 'npm:real@^1').
    """
    at = spec.find("@", 1)
    if at <= 0:
        return spec, ""
    return spec[:at], spec[at + 1 :]


_SEMVER = re.compile(r"^\d+\.\d+\.\d+[0-9A-Za-z.+-]*$")


def yarn_lock(project):
    """Yarn classic (v1) and Yarn Berry (v2+) lockfiles."""
    project = pathlib.Path(project)
    text = _read_text(project / "yarn.lock")
    if not text:
        return []
    declared = _package_json_declared(project)
    out, seen = [], set()
    header, version, resolution = None, None, None

    def flush():
        if header is None:
            return
        if resolution is not None:  # Berry: resolution is authoritative
            name, ref = _split_spec(resolution)
            if not ref.startswith("npm:"):
                return  # workspace:, patch:, link:, portal:, file:, git
            ver = ref[4:]
        else:  # Classic: name from the first spec, version from the 'version' line
            first = header.split(",")[0].strip().strip('"')
            name, rng = _split_spec(first)
            if rng.startswith("npm:"):  # alias "foo@npm:real-pkg@^1"
                name, _ = _split_spec(rng[4:])
            elif rng.startswith(("file:", "link:", "workspace:", "git", "http", "portal:")):
                return
            ver = version
        if name and ver and _SEMVER.match(ver) and (name, ver) not in seen:
            seen.add((name, ver))
            out.append(("npm", name, ver, _direct_flag_npm(name, declared)))

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            flush()
            header = line.rstrip(":").strip()
            version = resolution = None
            if header == "__metadata":
                header = None
            continue
        stripped = line.strip()
        if line.startswith("  ") and not line.startswith("   "):
            match = re.match(r'^version:?\s+"?([^"\s]+)"?$', stripped)
            if match:
                version = match.group(1)
            match = re.match(r'^resolution:\s+"?([^"]+?)"?$', stripped)
            if match:
                resolution = match.group(1)
    flush()
    return out


def _direct_flag_npm(name, declared):
    if not declared:
        return "unknown"
    return "direct" if name in declared else "transitive"


def pnpm_lock(project):
    """pnpm lockfile v5, v6 and v9 (packages and snapshots sections)."""
    project = pathlib.Path(project)
    text = _read_text(project / "pnpm-lock.yaml")
    if not text:
        return []
    declared = _package_json_declared(project)
    major = re.search(r"^lockfileVersion:\s*'?(\d+)", text, re.M)
    v5 = bool(major) and int(major.group(1)) <= 5
    out, seen, section = [], set(), None
    for line in text.splitlines():
        if line and not line.startswith(" "):
            section = line.split(":")[0].strip()
            continue
        if section not in ("packages", "snapshots"):
            continue
        match = re.match(r"^  (['\"]?)(\S.*?)\1:\s*(\{\})?\s*$", line)
        if not match:
            continue
        key = match.group(2).lstrip("/")
        key = re.sub(r"\(.*$", "", key)  # v6/v9 peer suffix: foo@1.0.0(react@18.2.0)
        if v5:
            name, _, ver = key.rpartition("/")
            ver = ver.split("_")[0]  # v5 peer suffix: 1.0.0_react@17.0.2
        else:
            name, ver = _split_spec(key)
        if not name or not _SEMVER.match(ver or ""):
            continue  # file:, link:, git or tarball URLs
        if (name, ver) not in seen:
            seen.add((name, ver))
            out.append(("npm", name, ver, _direct_flag_npm(name, declared)))
    return out


def _inside_node_modules(path):
    return "node_modules" in pathlib.Path(path).parts


def node_modules_tree(root, limit=50000):
    """Every package under a node_modules tree (used for global npm installs).

    Symlinks are followed only when they point into another node_modules folder, which is
    how some installers place registry packages. Symlinks to ordinary folders are
    ``npm link`` checkouts of local projects and are skipped so their names stay private.
    Real paths are tracked, so link cycles cannot cause endless walking.
    """
    out, seen, stack = [], set(), [pathlib.Path(root)]
    visited = set()
    while stack and len(out) < limit:
        directory = stack.pop()
        real_dir = os.path.realpath(directory)
        if real_dir in visited:
            continue
        visited.add(real_dir)
        try:
            children = sorted(p for p in directory.iterdir() if p.is_dir())
        except OSError:
            continue
        for child in children:
            if child.name.startswith("."):
                continue
            if child.is_symlink():
                target = os.path.realpath(child)
                if not _inside_node_modules(target):
                    continue  # npm link to a local project
                # The linked package's dependencies are hoisted next to it.
                stack.append(pathlib.Path(target).parent)
            if child.name.startswith("@"):
                stack.append(child)  # scope folder holds the real packages
                continue
            try:
                manifest = json.loads((child / "package.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                manifest = None
            if isinstance(manifest, dict):
                name, version = manifest.get("name"), manifest.get("version")
                if isinstance(name, str) and isinstance(version, str):
                    if (name, version) not in seen and _SEMVER.match(version):
                        seen.add((name, version))
                        out.append(("npm", name, version, "unknown"))
            nested = child / "node_modules"
            if nested.is_dir():
                stack.append(nested)
    return out


# ------------------------------------------------------------------- project detection

NPM_LOCKFILES = {
    "package-lock.json": npm_lock,
    "yarn.lock": yarn_lock,
    "pnpm-lock.yaml": pnpm_lock,
}
PYTHON_LOCKFILES = {
    "poetry.lock": poetry_lock,
    "uv.lock": uv_lock,
    "Pipfile.lock": pipfile_lock,
}


def project_lockfiles(directory, files):
    """Parse every supported lockfile in one folder.

    Returns ``(label, records)`` or ``None``. The label names the sources, for example
    ``"npm (yarn.lock)"`` or ``"npm (pnpm-lock.yaml) + Python (uv.lock)"``.
    """
    parts, records, seen = [], [], set()
    for eco, table in (("npm", NPM_LOCKFILES), ("Python", PYTHON_LOCKFILES)):
        used = [name for name in table if name in files]
        if not used:
            continue
        parts.append(f"{eco} ({', '.join(used)})")
        for name in used:
            for record in table[name](directory):
                key = (record[0], record[1], record[2])
                if key not in seen:
                    seen.add(key)
                    records.append(record)
    return (" + ".join(parts), records) if parts else None


# ----------------------------------------------------------------- global locations


def global_candidates(home=None, environ=None, platform=None):
    """Well-known global install folders. Returns ``[(path, kind)]``; may not exist."""
    home = pathlib.Path(home or pathlib.Path.home())
    environ = os.environ if environ is None else environ
    platform = platform or sys.platform
    npm, py = [], []

    def npm_root(prefix):
        prefix = pathlib.Path(prefix)
        return prefix / "node_modules" if platform == "win32" else prefix / "lib" / "node_modules"

    prefix = environ.get("NPM_CONFIG_PREFIX") or environ.get("npm_config_prefix")
    if prefix:
        npm.append(npm_root(prefix))
    # Derive the default global prefix from where the node binary lives (no execution):
    # <prefix>/bin/node on POSIX, <prefix>\node.exe on Windows.
    node = which("node", path=environ.get("PATH"))
    if node:
        node_dir = pathlib.Path(node).resolve().parent
        npm.append(npm_root(node_dir if platform == "win32" else node_dir.parent))
    if platform == "win32":
        appdata = environ.get("APPDATA")
        if appdata:
            npm.append(pathlib.Path(appdata) / "npm" / "node_modules")
        local = environ.get("LOCALAPPDATA")
        if local:
            py += [
                pathlib.Path(p)
                for p in glob.glob(
                    str(pathlib.Path(local) / "Programs/Python/Python3*/Lib/site-packages")
                )
            ]
        appdata = environ.get("APPDATA")
        if appdata:
            py += [
                pathlib.Path(p)
                for p in glob.glob(str(pathlib.Path(appdata) / "Python/Python3*/site-packages"))
            ]
    else:
        npm += [
            pathlib.Path("/usr/local/lib/node_modules"),
            pathlib.Path("/usr/lib/node_modules"),
            pathlib.Path("/opt/homebrew/lib/node_modules"),
            home / ".npm-global/lib/node_modules",
        ]
        npm += [
            pathlib.Path(p) for p in glob.glob(str(home / ".nvm/versions/node/*/lib/node_modules"))
        ]
        for pattern in (
            home / ".local/lib/python3*/site-packages",
            home / "Library/Python/3*/lib/python/site-packages",
            pathlib.Path("/usr/local/lib/python3*/site-packages"),
            pathlib.Path("/usr/local/lib/python3*/dist-packages"),
            pathlib.Path("/usr/lib/python3/dist-packages"),
            pathlib.Path("/opt/homebrew/lib/python3*/site-packages"),
        ):
            py += [pathlib.Path(p) for p in glob.glob(str(pattern))]
    # pipx keeps each tool in its own venv
    pipx = []
    for base in (home / ".local/pipx/venvs", home / ".local/share/pipx/venvs"):
        pipx += [pathlib.Path(p) for p in glob.glob(str(base / "*"))]

    # De-duplicate by real path: distros often symlink site-packages -> dist-packages.
    out, seen = [], set()
    for paths, kind in ((npm, "npm global"), (py, "Python global"), (pipx, "Python pipx")):
        for path in paths:
            try:
                real = os.path.realpath(path)
            except OSError:
                real = str(path)
            if real not in seen:
                seen.add(real)
                out.append((str(path), kind))
    return out


def read_global(path, kind):
    if kind == "npm global":
        return node_modules_tree(path)
    if kind == "Python pipx":
        return python_env(path)
    return site_packages_records(path)
