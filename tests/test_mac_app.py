import plistlib

from exitrisk import __version__
from exitrisk.mac_app import APP_NAME, write_bundle


def test_bundle_is_a_launchable_app(tmp_path):
    app = write_bundle(tmp_path, port=8741, exitrisk="/opt/x it's/exitrisk", icon=False)
    assert app.name == f"{APP_NAME}.app"
    info = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    assert info["CFBundleExecutable"] == "launch" and info["CFBundleShortVersionString"] == __version__
    launch = app / "Contents" / "MacOS" / "launch"
    assert launch.stat().st_mode & 0o111
    text = launch.read_text()
    assert 'URL="http://127.0.0.1:8741/"' in text and "--port 8741" in text
    assert "EXITRISK='/opt/x it'\\''s/exitrisk'" in text
    # installing again replaces the old bundle
    assert write_bundle(tmp_path, icon=False) == app
