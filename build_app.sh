#!/bin/bash
# Build Uwatch.app - a self-contained bundle whose Info.plist carries the
# Bluetooth usage description macOS demands before any process may use BLE.
set -euo pipefail

cd "$(dirname "$0")"
PYTHON="${PYTHON:-$(command -v python3.13 || command -v python3)}"
APP="${1:-$PWD/Uwatch.app}"
CONTENTS="$APP/Contents"

echo "building $APP with $PYTHON"
rm -rf "$APP"
mkdir -p "$CONTENTS"

# A venv laid out as a bundle: Contents/MacOS is the venv's bin directory, so
# the interpreter that actually runs is inside the bundle and macOS reads our
# Info.plist when the process asks for Bluetooth access.
"$PYTHON" -m venv --copies "$CONTENTS"
mv "$CONTENTS/bin" "$CONTENTS/MacOS"

PY_EXE="$(cd "$CONTENTS/MacOS" && ls python3.* 2>/dev/null | grep -E '^python3\.[0-9]+$' | head -1)"
[ -n "$PY_EXE" ] || { echo "could not find the interpreter copy in the bundle" >&2; exit 1; }

# macOS framework builds ship bin/python3.x as a stub that re-execs the
# framework's own Python.app, which would bypass our Info.plist. Swap in the
# real interpreter binary so the process stays inside this bundle.
FW_APP="$("$PYTHON" - <<'PYFIND'
import sysconfig, sys, pathlib
prefix = sysconfig.get_config_var("PYTHONFRAMEWORKPREFIX")
name = sysconfig.get_config_var("PYTHONFRAMEWORK")
if prefix and name:
    ver = f"{sys.version_info.major}.{sys.version_info.minor}"
    cand = pathlib.Path(prefix) / f"{name}.framework" / "Versions" / ver \
        / "Resources" / f"{name}.app" / "Contents" / "MacOS" / name
    if cand.exists():
        print(cand)
PYFIND
)"
if [ -n "$FW_APP" ]; then
    # Only keep the swap if the result actually runs and still resolves this
    # bundle's venv. Where several Pythons are installed (CI runners, a
    # python.org build alongside Homebrew) sysconfig can report a framework
    # belonging to a different installation; copying that binary out of its
    # signed framework gets it killed outright.
    BACKUP="$CONTENTS/MacOS/.$PY_EXE.venv"
    cp "$CONTENTS/MacOS/$PY_EXE" "$BACKUP"
    cp "$FW_APP" "$CONTENTS/MacOS/$PY_EXE"
    chmod +x "$CONTENTS/MacOS/$PY_EXE"

    WANT="$(cd "$CONTENTS" && pwd -P)"
    GOT="$("$CONTENTS/MacOS/$PY_EXE" -c \
        'import os, sys; print(os.path.realpath(sys.prefix))' 2>/dev/null || true)"

    if [ "$GOT" = "$WANT" ]; then
        echo "using framework interpreter $FW_APP"
        rm -f "$BACKUP"
    else
        echo "warning: $FW_APP does not belong to this venv (sys.prefix=${GOT:-<killed>})" >&2
        echo "         keeping the venv's own interpreter; if macOS denies Bluetooth," >&2
        echo "         rebuild with PYTHON=/path/to/matching/python3" >&2
        mv "$BACKUP" "$CONTENTS/MacOS/$PY_EXE"
        chmod +x "$CONTENTS/MacOS/$PY_EXE"
    fi
fi

cat > "$CONTENTS/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Uwatch</string>
    <key>CFBundleDisplayName</key><string>Uwatch</string>
    <key>CFBundleIdentifier</key><string>local.uwatch5s</string>
    <key>CFBundleVersion</key><string>0.1.0</string>
    <key>CFBundleShortVersionString</key><string>0.1.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleExecutable</key><string>$PY_EXE</string>
    <key>LSBackgroundOnly</key><true/>
    <key>NSBluetoothAlwaysUsageDescription</key>
    <string>Uwatch talks to your Uwatch 5S smartwatch over Bluetooth to set the time, manage alarms and read step counts.</string>
    <key>NSBluetoothPeripheralUsageDescription</key>
    <string>Uwatch talks to your Uwatch 5S smartwatch over Bluetooth.</string>
</dict>
</plist>
PLIST

"$CONTENTS/MacOS/$PY_EXE" -m pip install --quiet --upgrade pip
"$CONTENTS/MacOS/$PY_EXE" -m pip install --quiet .

rm -rf "$CONTENTS/bin"   # pip recreates the venv script dir; the bundle uses MacOS

# Ad-hoc sign so TCC can remember the grant instead of re-prompting.
codesign --force --deep --sign - "$APP" 2>/dev/null || \
    echo "warning: could not codesign; macOS may re-ask for Bluetooth access" >&2

cp bundle_main.py "$CONTENTS/bundle_main.py"
cp uwatch_run.sh "$CONTENTS/MacOS/uwatch-run"
chmod +x "$CONTENTS/MacOS/uwatch-run"

echo
echo "done. run it with:"
echo "  $CONTENTS/MacOS/uwatch-run scan"
echo
echo "optionally put it on your PATH:"
echo "  ln -sf \"$CONTENTS/MacOS/uwatch-run\" /usr/local/bin/uwatch"
