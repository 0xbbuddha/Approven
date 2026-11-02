#!/usr/bin/env bash
# Reverses dist/install.sh: removes the PAM line, stops the service,
# removes the binaries. Run with sudo as your normal user:
#   sudo ./dist/uninstall.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run this with sudo." >&2
    exit 1
fi
if [[ -z "${SUDO_USER:-}" ]]; then
    echo "Run this with sudo as your normal user, not as a root login." >&2
    exit 1
fi

PAM_FILE=/etc/pam.d/sudo
if grep -qF "approve-helper" "$PAM_FILE" 2>/dev/null; then
    cp -a "$PAM_FILE" "$PAM_FILE.bak-uninstall-$(date +%Y%m%d-%H%M%S)"
    grep -vF "approve-helper" "$PAM_FILE" > "$PAM_FILE.new"
    mv "$PAM_FILE.new" "$PAM_FILE"
    echo "Removed the PAM line from $PAM_FILE."
fi

SUDO_UID=$(id -u "$SUDO_USER")
USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
sudo -u "$SUDO_USER" env XDG_RUNTIME_DIR="/run/user/$SUDO_UID" systemctl --user disable --now approved.service 2>/dev/null || true
rm -f "$USER_HOME/.config/systemd/user/approved.service"
sudo -u "$SUDO_USER" env XDG_RUNTIME_DIR="/run/user/$SUDO_UID" systemctl --user daemon-reload 2>/dev/null || true

rm -f /usr/local/bin/approved /usr/local/bin/approve-helper /usr/local/bin/approve-cli

echo "Enrolled keys are left in /etc/approven. Remove with:"
echo "  sudo rm -rf /etc/approven"
echo "Done."
