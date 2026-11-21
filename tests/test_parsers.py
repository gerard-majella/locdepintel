"""Lockfile and environment parsers, tested against fixtures in each tool's real format.

Fixtures are stored as ``*.fixture`` so GitHub's dependency graph does not treat them as
this repository's own dependencies; each test copies them to a temp folder first.
"""

import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from locdepintel import core, parsers

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def materialize(name):
    """Copy fixtures/<name>/*.fixture into a temp folder with their real file names."""
    target = pathlib.Path(tempfile.mkdtemp())
    for src in (FIXTURES / name).glob("*.fixture"):
        shutil.copy(src, target / src.name.removesuffix(".fixture"))
    return target


def as_set(records):
    return {(name, version, direct) for _eco, name, version, direct in records}


class YarnTests(unittest.TestCase):
    def test_classic_v1(self):
        records = parsers.yarn_lock(materialize("yarn-classic"))
        self.assertEqual(
            as_set(records),
            {
                ("@babel/code-frame", "7.12.13", "transitive"),
                ("lodash", "4.17.21", "direct"),
                ("string-width", "4.2.3", "transitive"),  # alias resolved to the real package
            },
        )  # file: dependency skipped

    def test_berry(self):
        records = parsers.yarn_lock(materialize("yarn-berry"))
        self.assertEqual(
            {(n, v) for _e, n, v, _d in records},
            {("@babel/code-frame", "7.24.2"), ("lodash", "4.17.21"), ("string-width", "4.2.3")},
        )  # workspace and patch entries skipped


class PnpmTests(unittest.TestCase):
    def test_v5_slash_format_with_peer_suffix(self):
        names = {(n, v) for _e, n, v, _d in parsers.pnpm_lock(materialize("pnpm-v5"))}
        self.assertEqual(names, {("@babel/code-frame", "7.12.13"), ("react-dom", "17.0.2")})

    def test_v6_at_format_skips_local_directories(self):
        names = {(n, v) for _e, n, v, _d in parsers.pnpm_lock(materialize("pnpm-v6"))}
        self.assertEqual(names, {("@babel/code-frame", "7.24.2"), ("react-dom", "18.2.0")})

    def test_v9_packages_and_snapshots_deduplicated(self):
        records = parsers.pnpm_lock(materialize("pnpm-v9"))
        self.assertEqual(
            as_set(records),
            {
                ("@babel/code-frame", "7.24.2", "transitive"),
                ("lodash", "4.17.21", "direct"),
                ("react-dom", "18.2.0", "transitive"),
            },
        )
        self.assertNotIn("@internal/ui", {r[1] for r in records})  # workspace link


class PythonLockfileTests(unittest.TestCase):
    def test_poetry_skips_private_index_and_local_paths(self):
        records = parsers.poetry_lock(materialize("poetry"))
        self.assertEqual(
            as_set(records),
            {("certifi", "2024.2.2", "transitive"), ("requests", "2.31.0", "direct")},
        )

    def test_uv_only_public_registry(self):
        records = parsers.uv_lock(materialize("uv"))
        self.assertEqual(
            as_set(records),
            {("httpx", "0.27.0", "direct"), ("sniffio", "1.3.1", "transitive")},
        )

    def test_pipfile_lock(self):
        records = parsers.pipfile_lock(materialize("pipenv"))
        self.assertEqual(
            {(n, v) for _e, n, v, _d in records}, {("flask", "3.0.3"), ("pytest", "8.2.0")}
        )

    def test_all_python_records_are_pypi(self):
        for name, func in (("poetry", parsers.poetry_lock), ("uv", parsers.uv_lock)):
            self.assertTrue(all(r[0] == "PyPI" for r in func(materialize(name))))


class PnpmEmptySnapshotTests(unittest.TestCase):
    def test_snapshot_only_entry_written_as_empty_object(self):
        target = pathlib.Path(tempfile.mkdtemp())
        (target / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '9.0'\n\nsnapshots:\n\n  ms@2.1.3: {}\n"
        )
        self.assertEqual([(r[1], r[2]) for r in parsers.pnpm_lock(target)], [("ms", "2.1.3")])


class MalformedInputTests(unittest.TestCase):
    def test_garbage_never_raises(self):
        target = pathlib.Path(tempfile.mkdtemp())
        junk = "\x00\xff{[ not a lockfile ::: ]]"
        for fname in (
            "yarn.lock",
            "pnpm-lock.yaml",
            "poetry.lock",
            "uv.lock",
            "Pipfile.lock",
            "package-lock.json",
            "package.json",
            "pyproject.toml",
        ):
            (target / fname).write_text(junk)
        for func in (
            parsers.yarn_lock,
            parsers.pnpm_lock,
            parsers.poetry_lock,
            parsers.uv_lock,
            parsers.pipfile_lock,
            parsers.npm_lock,
        ):
            self.assertEqual(func(target), [], func.__name__)

    def test_oversized_lockfile_skipped(self):
        target = pathlib.Path(tempfile.mkdtemp())
        (target / "yarn.lock").write_text("x")
        with mock.patch.object(parsers, "MAX_LOCKFILE_BYTES", 0):
            self.assertEqual(parsers.yarn_lock(target), [])


class EnvironmentTests(unittest.TestCase):
    def make_site(self, site, packages, egg=()):
        site.mkdir(parents=True)
        for name, version in packages:
            d = site / f"{name}-{version}.dist-info"
            d.mkdir()
            (d / "METADATA").write_text(
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            )
        for name, version in egg:  # Debian-style single-file egg-info
            (site / f"{name}-{version}.egg-info").write_text(f"Name: {name}\nVersion: {version}\n")

    def test_conda_env_and_nested_envs_discovered(self):
        root = pathlib.Path(tempfile.mkdtemp())
        base = root / "miniconda3"
        (base / "conda-meta").mkdir(parents=True)
        self.make_site(base / "lib/python3.12/site-packages", [("numpy", "1.26.4")])
        env = base / "envs/ml"
        (env / "conda-meta").mkdir(parents=True)
        self.make_site(env / "lib/python3.11/site-packages", [("torch", "2.3.0")])
        found, warnings = core.discover([root])
        self.assertFalse(warnings)
        by_path = {p: (label, {r[1] for r in recs}) for p, label, recs in found}
        self.assertEqual(by_path[str(base)], ("Python conda", {"numpy"}))
        self.assertEqual(by_path[str(env)], ("Python conda", {"torch"}))

    def test_windows_layout_and_egg_info(self):
        env = pathlib.Path(tempfile.mkdtemp()) / "venv"
        self.make_site(env / "Lib/site-packages", [("six", "1.16.0")], egg=[("chardet", "4.0.0")])
        self.assertEqual(
            {(r[1], r[2]) for r in parsers.python_env(env)},
            {("six", "1.16.0"), ("chardet", "4.0.0")},
        )

    def test_project_with_npm_and_python_lockfiles(self):
        project = pathlib.Path(tempfile.mkdtemp()) / "fullstack"
        shutil.copytree(materialize("pnpm-v9"), project)
        for f in materialize("uv").iterdir():
            shutil.copy(f, project / f.name)
        found, _ = core.discover([project.parent])
        self.assertEqual(len(found), 1)
        path, label, records = found[0]
        self.assertEqual(label, "npm (pnpm-lock.yaml) + Python (uv.lock)")
        self.assertEqual({r[0] for r in records}, {"npm", "PyPI"})


class GlobalInstallTests(unittest.TestCase):
    def setUp(self):
        self.home = pathlib.Path(tempfile.mkdtemp())

    def test_candidates_cover_common_locations(self):
        (self.home / ".nvm/versions/node/v20.11.0/lib/node_modules").mkdir(parents=True)
        (self.home / ".local/lib/python3.12/site-packages").mkdir(parents=True)
        (self.home / ".local/pipx/venvs/black").mkdir(parents=True)
        posix = dict(parsers.global_candidates(home=self.home, environ={}, platform="linux"))
        self.assertEqual(
            posix[str(self.home / ".nvm/versions/node/v20.11.0/lib/node_modules")], "npm global"
        )
        self.assertEqual(
            posix[str(self.home / ".local/lib/python3.12/site-packages")], "Python global"
        )
        self.assertEqual(posix[str(self.home / ".local/pipx/venvs/black")], "Python pipx")
        win = dict(
            parsers.global_candidates(
                home=self.home, environ={"APPDATA": "C:/AppData"}, platform="win32"
            )
        )
        self.assertIn(str(pathlib.Path("C:/AppData/npm/node_modules")), win)

    @unittest.skipIf(sys.platform == "win32", "POSIX symlink/executable semantics")
    def test_symlinked_site_packages_counted_once(self):
        real = self.home / ".local/lib/python3.12/dist-packages"
        real.mkdir(parents=True)
        (self.home / ".local/lib/python3.12/site-packages").symlink_to(real)
        (self.home / ".local/lib/python3.13/site-packages").mkdir(parents=True)
        found = [
            p
            for p, k in parsers.global_candidates(home=self.home, environ={}, platform="linux")
            if p.startswith(str(self.home / ".local/lib/python3.12"))
        ]
        self.assertEqual(len(found), 1)

    @unittest.skipIf(sys.platform == "win32", "POSIX symlink/executable semantics")
    def test_npm_prefix_derived_from_node_binary_location(self):
        prefix = self.home / "opt/node22"
        (prefix / "bin").mkdir(parents=True)
        node = prefix / "bin/node"
        node.write_text("#!/bin/sh\n")
        node.chmod(0o755)
        found = dict(
            parsers.global_candidates(
                home=self.home, environ={"PATH": str(prefix / "bin")}, platform="linux"
            )
        )
        self.assertEqual(found.get(str(prefix / "lib/node_modules")), "npm global")

    def test_global_node_modules_tree_includes_bundled_and_scoped(self):
        nm = self.home / "lib/node_modules"
        for rel, name, ver in (
            ("npm", "npm", "10.5.0"),
            ("npm/node_modules/semver", "semver", "7.6.0"),
            ("@angular/cli", "@angular/cli", "17.3.0"),
        ):
            (nm / rel).mkdir(parents=True)
            (nm / rel / "package.json").write_text(json.dumps({"name": name, "version": ver}))
        self.assertEqual(
            {(r[1], r[2]) for r in parsers.node_modules_tree(nm)},
            {("npm", "10.5.0"), ("semver", "7.6.0"), ("@angular/cli", "17.3.0")},
        )

    @unittest.skipIf(sys.platform == "win32", "POSIX symlink semantics")
    def test_symlinked_registry_installs_followed_but_npm_link_skipped(self):
        tools = self.home / "opt/node-tools/node_modules"
        for name, ver in (("typescript", "5.4.0"), ("eslint", "9.0.0"), ("acorn", "8.11.0")):
            (tools / name).mkdir(parents=True)
            (tools / name / "package.json").write_text(json.dumps({"name": name, "version": ver}))
        project = self.home / "code/my-private-cli"  # what `npm link` points at
        project.mkdir(parents=True)
        (project / "package.json").write_text('{"name":"@corp/private-cli","version":"1.0.0"}')
        nm = self.home / "global/lib/node_modules"
        nm.mkdir(parents=True)
        (nm / "typescript").symlink_to(tools / "typescript")
        (nm / "eslint").symlink_to(tools / "eslint")
        (nm / "private-cli").symlink_to(project)
        (tools / "loop").symlink_to(nm)  # a cycle must not hang the walk
        names = {r[1] for r in parsers.node_modules_tree(nm)}
        self.assertEqual(names, {"typescript", "eslint", "acorn"})  # acorn: hoisted dependency

    def test_include_global_is_opt_in_and_retires_when_turned_off(self):
        data = self.home / "data"
        data.mkdir()
        nm = self.home / "global/node_modules"
        (nm / "evil-cli").mkdir(parents=True)
        (nm / "evil-cli/package.json").write_text('{"name":"evil-cli","version":"1.0.0"}')
        with (
            mock.patch.object(core, "home_data", lambda: data),
            mock.patch.object(parsers, "global_candidates", lambda: [(str(nm), "npm global")]),
        ):
            cfg = {"roots": [], "include_global": False}
            core.scan(cfg)
            self.assertEqual(core.inventory(), [])
            core.scan(dict(cfg, include_global=True))
            self.assertEqual([p["name"] for p in core.inventory()], ["evil-cli"])
            result = core.scan(cfg)
            self.assertEqual(core.inventory(), [])
            self.assertEqual(result["out_of_scope"], 1)


if __name__ == "__main__":
    unittest.main()
