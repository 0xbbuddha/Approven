#!/usr/bin/env bash
# Installs approven: builds the 3 binaries, installs them to
# /usr/local/bin, enables the user service, and adds the PAM line to
# sudo. Run with sudo from the repository root:
#   sudo ./dist/install.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this with sudo." >&2
    exit 1
fi
if [[ -z "${SUDO_USER:-}" ]]; then
    echo "Run this with sudo as your normal user, not as a root login." >&2
    exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "Building..."
sudo -u "$SUDO_USER" go build -o bin/approved ./cmd/approved
sudo -u "$SUDO_USER" go build -o bin/approve-helper ./cmd/approve-helper
sudo -u "$SUDO_USER" go build -o bin/approve-cli ./cmd/approve-cli

echo "Installing binaries to /usr/local/bin..."
install -m 0755 -o root -g root bin/approved /usr/local/bin/approved
install -m 0755 -o root -g root bin/approve-helper /usr/local/bin/approve-helper
install -m 0755 -o root -g root bin/approve-cli /usr/local/bin/approve-cli

echo "Creating /etc/approven..."
install -d -m 0755 -o root -g root /etc/approven

echo "Adding the PAM line to /etc/pam.d/sudo..."
PAM_FILE=/etc/pam.d/sudo
PAM_LINE='auth	sufficient	pam_exec.so quiet stdout /usr/local/bin/approve-helper'
if grep -qF "pam_exec.so" "$PAM_FILE" 2>/dev/null && grep -qF "approve-helper" "$PAM_FILE"; then
    echo "  already present, skipping."
else
    cp -a "$PAM_FILE" "$PAM_FILE.bak-$(date +%Y%m%d-%H%M%S)"
    # Insert as the new first line of the file: PAM reads auth rules top
    # to bottom, and "sufficient" only short-circuits the rules after it,
    # so this must run before the password rule, not after.
    { printf '%s\n' "$PAM_LINE"; cat "$PAM_FILE"; } > "$PAM_FILE.new"
    mv "$PAM_FILE.new" "$PAM_FILE"
    echo "  added. Backup at $PAM_FILE.bak-*"
fi

echo "Installing the systemd user service..."
USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
install -d -m 0755 -o "$SUDO_USER" -g "$SUDO_USER" "$USER_HOME/.config/systemd/user"
install -m 0644 -o "$SUDO_USER" -g "$SUDO_USER" dist/approved.service "$USER_HOME/.config/systemd/user/approved.service"

SUDO_UID=$(id -u "$SUDO_USER")
sudo -u "$SUDO_USER" env XDG_RUNTIME_DIR="/run/user/$SUDO_UID" systemctl --user daemon-reload
sudo -u "$SUDO_USER" env XDG_RUNTIME_DIR="/run/user/$SUDO_UID" systemctl --user enable approved.service
# restart, not "enable --now": on a re-run, the service is usually
# already active, and --now only starts a stopped unit - it never picks
# up a changed unit file or a rebuilt binary on its own.
sudo -u "$SUDO_USER" env XDG_RUNTIME_DIR="/run/user/$SUDO_UID" systemctl --user restart approved.service

echo
echo "Installed. Next:"
echo "  1. Install the phone app and open it."
echo "  2. sudo approve-cli enroll"
echo "  3. Test: sudo -k && sudo true"
echo
echo "Uninstall: dist/uninstall.sh (run with sudo)"
