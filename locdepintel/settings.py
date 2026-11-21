"""Where LocDepIntel keeps its data, the user's settings, and timestamps."""

import json
import os
import pathlib
import sys
from datetime import datetime, timezone

APP = "LocDepIntel"


def timestamp():
    # Millisecond precision: two quick checks in the same second must still order correctly.
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def home_data():
    if sys.platform == "darwin":
        base = pathlib.Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = pathlib.Path(os.getenv("LOCALAPPDATA", pathlib.Path.home()))
    else:
        base = pathlib.Path(os.getenv("XDG_DATA_HOME", pathlib.Path.home() / ".local" / "share"))
    d = base / APP
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path():
    return home_data() / "config.json"


def suggested_roots():
    """Only user-owned conventional directories; explicit consent is needed before scanning."""
    home = pathlib.Path.home()
    names = ("Documents", "Desktop", "Developer", "Projects", "Code", "src", "Downloads")
    return [
        {
            "name": name,
            "path": str(home / name),
            "exists": (home / name).is_dir(),
            "default": name in ("Documents", "Desktop", "Developer", "Projects", "Code", "src"),
        }
        for name in names
    ]


def load_config():
    try:
        config = json.loads(config_path().read_text())
        if isinstance(config, dict):
            return config
    except (FileNotFoundError, ValueError):
        pass
    return {
        "roots": [str(pathlib.Path.home() / "Documents")],
        "max_depth": 7,
        "max_dirs": 30000,
        "include_global": False,
    }


def save_config(c):
    config_path().write_text(json.dumps(c, indent=2))
    return c
