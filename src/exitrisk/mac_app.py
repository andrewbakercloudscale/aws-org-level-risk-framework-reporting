"""A macOS app for the console: ``exitrisk app`` puts "AWS Cloud Risk Review" in ~/Applications, so it is
found from Spotlight, Launchpad and the Dock like any other app. Opening it starts the console if it is not
running and opens the page in the default browser."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from importlib import resources
from pathlib import Path

from . import __version__

APP_NAME = "AWS Cloud Risk Review"
BUNDLE_ID = "consulting.cloudscale.exitrisk"
AGENT = "com.exitrisk.console"  # the LaunchAgent some installs keep the console running with

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>{name}</string>
  <key>CFBundleDisplayName</key><string>{name}</string>
  <key>CFBundleIdentifier</key><string>{bundle_id}</string>
  <key>CFBundleVersion</key><string>{version}</string>
  <key>CFBundleShortVersionString</key><string>{version}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>launch</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
"""

# The console may already run (from a terminal or the LaunchAgent): then the page is only opened.
# Otherwise the LaunchAgent is started if there is one, else the console in the background.
LAUNCH = """#!/bin/bash
URL="http://127.0.0.1:{port}/"
EXITRISK={exitrisk}
LOG="$HOME/Library/Logs/exitrisk-console.log"
up() {{ /usr/bin/curl -fsS -m 2 "${{URL}}api/health" >/dev/null 2>&1; }}
if ! up; then
  if /bin/launchctl print "gui/$(id -u)/{agent}" >/dev/null 2>&1; then
    /bin/launchctl kickstart "gui/$(id -u)/{agent}"
  elif [ -x "$EXITRISK" ]; then
    mkdir -p "$(dirname "$LOG")"
    nohup "$EXITRISK" serve --no-browser --port {port} >>"$LOG" 2>&1 &
  fi
  for _ in $(seq 1 40); do up && break; sleep 0.5; done
fi
if up; then
  /usr/bin/open "$URL"
else
  /usr/bin/osascript -e 'display alert "{name}" message "The console did not start. See {log_hint}."' >/dev/null
fi
"""


def _exitrisk_path() -> str:
    """The exitrisk command of this install: beside the running Python, else on the PATH."""
    here = Path(sys.executable).with_name("exitrisk")
    return str(here) if here.exists() else (shutil.which("exitrisk") or str(here))


def write_bundle(dest: Path, port: int = 8740, exitrisk: str | None = None, icon: bool = True) -> Path:
    """Write the .app bundle under ``dest`` (replacing an older one) and return its path."""
    app = dest / f"{APP_NAME}.app"
    if app.exists():
        shutil.rmtree(app)
    macos = app / "Contents" / "MacOS"
    macos.mkdir(parents=True)
    (app / "Contents" / "Resources").mkdir()
    (app / "Contents" / "Info.plist").write_text(
        INFO_PLIST.format(name=APP_NAME, bundle_id=BUNDLE_ID, version=__version__), encoding="utf-8"
    )
    script = macos / "launch"
    exe = exitrisk or _exitrisk_path()
    script.write_text(
        LAUNCH.format(
            port=port,
            exitrisk="'" + exe.replace("'", "'\\''") + "'",
            agent=AGENT,
            name=APP_NAME,
            log_hint="~/Library/Logs/exitrisk-console.log",
        ),
        encoding="utf-8",
    )
    script.chmod(0o755)
    if icon:
        _icon(app / "Contents" / "Resources" / "icon.icns")
    return app


def _icon(out: Path) -> bool:
    """The console's favicon as an .icns (macOS tools only; the app works without it)."""
    svg = resources.files("exitrisk").joinpath("web/favicon.svg")
    with tempfile.TemporaryDirectory() as tmp, resources.as_file(svg) as src:
        base = Path(tmp) / "icon.png"
        if shutil.which("rsvg-convert"):
            made = subprocess.run(
                ["rsvg-convert", "-w", "1024", "-h", "1024", str(src), "-o", str(base)], capture_output=True
            )
        else:  # Quick Look renders SVG on every Mac
            made = subprocess.run(["qlmanage", "-t", "-s", "1024", "-o", tmp, str(src)], capture_output=True)
            ql = Path(tmp) / f"{Path(src).name}.png"
            if ql.exists():
                ql.rename(base)
        if made.returncode or not base.exists():
            return False
        iconset = Path(tmp) / "icon.iconset"
        iconset.mkdir()
        for size in (16, 32, 128, 256, 512):
            for scale in (1, 2):
                name = f"icon_{size}x{size}{'@2x' if scale == 2 else ''}.png"
                px = str(size * scale)
                subprocess.run(
                    ["sips", "-z", px, px, str(base), "--out", str(iconset / name)], capture_output=True, check=False
                )
        return (
            subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(out)], capture_output=True).returncode
            == 0
        )


def install(dest: Path | None = None, port: int = 8740) -> Path:
    """Install the app into ~/Applications (or ``dest``) and register it so Spotlight finds it at once."""
    if sys.platform != "darwin":
        raise RuntimeError(
            f"the app is for macOS; elsewhere open http://127.0.0.1:{port}/ and use the browser's Install app"
        )
    dest = dest or Path.home() / "Applications"
    dest.mkdir(parents=True, exist_ok=True)
    app = write_bundle(dest, port)
    lsreg = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
    if Path(lsreg).exists():
        subprocess.run([lsreg, "-f", str(app)], capture_output=True, check=False)
    subprocess.run(["touch", str(app)], check=False)  # Finder shows the new icon
    return app
