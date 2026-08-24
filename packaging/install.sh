#!/usr/bin/env bash
set -eu

SCRIPT_DIR=$(CDPATH= cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
BIN_DIR="${HOME}/.local/bin"
YES=0
NO_PATH=0

fail() { printf '%s\n' "OpenBOLA install failed: $1" >&2; exit 1; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin-dir) [ "$#" -ge 2 ] || fail "--bin-dir requires a directory"; BIN_DIR=$2; shift 2 ;;
    --yes) YES=1; shift ;;
    --no-path) NO_PATH=1; shift ;;
    *) fail "unknown option" ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || fail "macOS is required"
MACHINE=$(uname -m)
[ "$MACHINE" = "arm64" ] || [ "$MACHINE" = "x86_64" ] || fail "unsupported architecture"

EXECUTABLE="$SCRIPT_DIR/openbola"
MANIFEST="$SCRIPT_DIR/openbola.sha256"
[ -f "$EXECUTABLE" ] && [ ! -L "$EXECUTABLE" ] || fail "executable is missing or invalid"
[ -f "$MANIFEST" ] && [ ! -L "$MANIFEST" ] || fail "checksum manifest is missing or invalid"

EXPECTED=$(awk 'NF == 2 && $2 == "openbola" { print $1; count++ } END { if (count != 1) exit 1 }' "$MANIFEST") || fail "checksum manifest is invalid"
case "$EXPECTED" in (*[!0-9a-fA-F]*|'') fail "checksum manifest is invalid";; esac
[ "${#EXPECTED}" -eq 64 ] || fail "checksum manifest is invalid"
if command -v shasum >/dev/null 2>&1; then
  ACTUAL=$(shasum -a 256 "$EXECUTABLE" | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$EXECUTABLE" | awk '{print $1}')
else
  fail "no SHA-256 utility available"
fi
[ "$EXPECTED" = "$ACTUAL" ] || fail "checksum mismatch"

if [ -e "$BIN_DIR" ] && [ -L "$BIN_DIR" ]; then fail "destination directory is a symlink"; fi
if [ ! -e "$BIN_DIR" ]; then mkdir -p "$BIN_DIR" || fail "cannot create destination"; chmod 700 "$BIN_DIR" || fail "cannot secure destination"; fi
[ -d "$BIN_DIR" ] || fail "destination is not a directory"
DEST="$BIN_DIR/openbola"
if [ -L "$DEST" ]; then fail "destination executable is a symlink"; fi
if [ -e "$DEST" ] && [ "$YES" -ne 1 ]; then
  printf 'Replace %s? [y/N] ' "$DEST" >&2
  IFS= read -r answer || answer=""
  case "$answer" in [yY]|[yY][eE][sS]) ;; *) fail "replacement not confirmed";; esac
fi

TEMP=$(mktemp "$BIN_DIR/.openbola.XXXXXX") || fail "cannot create temporary file"
cleanup() { rm -f "$TEMP"; }
trap cleanup EXIT HUP INT TERM
cp "$EXECUTABLE" "$TEMP" || fail "cannot copy executable"
chmod 755 "$TEMP" || fail "cannot set executable mode"
mv -f "$TEMP" "$DEST" || fail "cannot replace executable"
trap - EXIT HUP INT TERM
printf 'Installed %s\n' "$DEST"

if [ "$NO_PATH" -eq 0 ]; then
  PROFILE=""
  case "$(basename "${SHELL:-}")" in
    zsh) PROFILE="${ZDOTDIR:-$HOME}/.zshrc" ;;
    bash) PROFILE="${HOME}/.bashrc" ;;
  esac
  if [ -n "$PROFILE" ]; then
    printf 'Add %s to PATH in %s? [y/N] ' "$BIN_DIR" "$PROFILE" >&2
    IFS= read -r answer || answer=""
    case "$answer" in
      [yY]|[yY][eE][sS])
        touch "$PROFILE" || fail "cannot update shell profile"
        grep -Fqx "export PATH=\"$BIN_DIR:\$PATH\"" "$PROFILE" 2>/dev/null ||
          printf 'export PATH="%s:$PATH"\n' "$BIN_DIR" >> "$PROFILE" || fail "cannot update shell profile" ;;
    esac
  fi
fi
