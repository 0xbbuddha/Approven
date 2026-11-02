<p align="center">
  <img src="docs/logo.png" alt="approven logo: a fingerprint turning into a checkmark, with Tux" width="260">
</p>

# Approven

Approve `sudo` with your phone's fingerprint. An EC P-256 key lives in
the Android Keystore and only signs after a biometric check; a
root-owned trust-anchor file on the computer holds its public half; a
PAM helper verifies a signature it rebuilds itself from its own PAM
environment, rather than trusting anything the network sends back.

## What's here

```
internal/protocol/      message format + ECDSA P-256 (shared contract with the phone)
internal/keyfile/       the /etc/approven/<user>.pub trust anchor, strict checks
internal/ipc/           local Unix socket, SO_PEERCRED-checked
internal/daemon/        relays local requests to whichever Transport reaches the phone
internal/phonetransport/ the real Transport: a TLS server the phone dials into
cmd/approved/           the daemon binary (runs as the user)
cmd/approve-helper/     the PAM-invoked binary (root) - verifies, never trusts
cmd/approve-cli/        enroll / status / remove
dist/                   systemd service, PAM line, install.sh / uninstall.sh
android/                the phone app (Kotlin, Jetpack Compose)
```

Every package under `internal/` and every `cmd/` has tests; run
`go test ./...`. The two invariants that matter most - a valid phone
signature is accepted, a signature over a different message is refused
even if everything else about the response looks right - are exercised
with real root privileges in `cmd/approve-helper`'s test suite, not
just mocked.

## Install

Every push to `main` builds and publishes a
[release](https://github.com/0xbbuddha/Approven/releases/latest) with an
Arch package, a `PKGBUILD`, a Linux binary tarball, and the Android APK.

### Arch Linux

```sh
makepkg -si   # from a checkout containing PKGBUILD
```

or grab the prebuilt `approven-*.pkg.tar.zst` from the latest release
and `sudo pacman -U` it. Either way, `pacman` prints the PAM line and
the remaining setup steps after install.

### From source

```sh
go build ./...   # sanity check
sudo ./dist/install.sh
```

This builds the 3 binaries, installs them to `/usr/local/bin`, adds one
line to `/etc/pam.d/sudo`, and enables `approved` as your systemd user
service. It backs up `/etc/pam.d/sudo` before touching it.

Then, on the phone, install the APK from the latest release (or build
your own: `cd android && ./gradlew assembleDebug`) and open it.

Release APKs are signed with a key kept out of this repo (CI reads it
from the `APPROVEN_KEYSTORE_B64` and `APPROVEN_KEYSTORE_PASSWORD`
secrets). Locally, `APPROVEN_KEYSTORE=/path/to/release.keystore` plus
`APPROVEN_KEYSTORE_PASSWORD` sign a release build; without them it
comes out unsigned.

### Pairing

1. On the phone, enter the computer's LAN IP and port `17165`, tap
   Connect. The app says "Not paired yet" until the next steps are done.
2. On the computer: `sudo approve-cli enroll`.
3. The phone shows a request; approving it asks for a fingerprint, then
   shows a 16-character code.
4. Type that code into the terminal running `enroll`.
5. Test: tap the logo in the app, or run `sudo -k && sudo true` - either
   way the phone asks instead of a password.

On Android 14+, also allow **full-screen alerts** for Approven
(Settings → Apps → Approven → Notifications). Without it a request
only lands in the notification shade instead of opening the approval
screen on its own.

## Using it

**In the terminal**, every sudo that goes through the phone prints a
4-character code:

```
Approve on A059 - check it shows code 3FA9 - or wait for the password prompt.
```

**On the phone**, the approval screen shows that same code, the exact
command (`sudo pacman -Syu`), the user, terminal and computer, and a
20-second countdown. Approve only when the code matches your terminal:
that is what tells your own sudo apart from one that something else
running as you started at the same moment. Deny, a cancelled
fingerprint, or the countdown running out all fall back to the password
prompt; once the computer stops waiting, the phone closes the request
and its notification.

**The app's home screen** shows:

- the live connection state - grey offline, amber connecting or
  connected but not paired, mint "Ready to approve";
- the paired computer, its pinned certificate, and buttons to
  disconnect, change its address, or forget it (available at any time);
- the last 20 approvals and denials.

**Tapping the logo** runs `sudo -k true` on the computer as a test. The
request comes straight back to the phone like any other, and the
computer shows a desktop notification when it starts and with the
result (`notify-send`; the test itself runs through `systemd-run
--user`, since the daemon's own unit sets `NoNewPrivileges`). Only the
paired phone can ask for a test, and the command is fixed.

`approve-cli status` shows whether the phone is currently connected and
what's enrolled. `sudo approve-cli remove` forgets the phone on the
computer side; "Forget this computer" in the app does the same on the
phone's side.

## Security model

- **The phone's fingerprint is the only way in.** The PAM helper builds
  the signed message itself (host, user, command, terminal, time, a
  fresh random nonce) and verifies the phone's ECDSA P-256 signature
  against the root-owned `/etc/approven/<user>.pub`. Nothing the
  daemon or the network sends back is trusted.
- **The key never leaves the phone.** It lives in the Android Keystore
  (StrongBox when available), signs only after a strong-biometric
  check, every time, and is destroyed if a new fingerprint is added.
- **Only the enrolled phone gets requests.** The phone authenticates
  with a TLS client certificate from a second Keystore key; enrollment
  pins it in the key file. Another device on the network can neither
  receive sudo requests nor push the real phone out.
- **Enrollment detects a man in the middle.** The signed enrollment
  covers both TLS certificates as the phone saw them; if they differ
  from the daemon's view, nothing is written.
- **The password always still works.** The PAM line is `sufficient`,
  so any failure falls through to the normal prompt.
- **Release APKs are signed with a key kept out of this repo**, so
  nobody else can ship an "update" that inherits the app's keys.

Upgrading from protocol v1 means enrolling again: run
`sudo approve-cli remove`, forget the computer in the app, and pair
again.

## Uninstall

```sh
sudo ./dist/uninstall.sh
```

Removes the PAM line (with a backup), stops the service, removes the
binaries. Leaves `/etc/approven` - remove by hand if you want the
enrolled key gone too.

## What's verified and what isn't

Everything in `internal/` and the 3 desktop `cmd/` binaries is tested,
including 2 root-privileged integration tests that actually exercise a
real signature verifying and a tampered one being refused.

The full phone-to-computer path (mutual-TLS pairing, biometric
signing, a full-screen approval prompt reaching the lock screen, the
logo's test sudo) has been exercised end to end on a real device, including the failure modes
that only show up there: a background service that cannot start an
Activity without a full-screen-intent notification, a notification
permission that has to be requested at runtime on Android 13+, writing
to a socket from a BiometricPrompt callback (the main thread, which
Android forbids for any network I/O), and a `singleInstance` Activity
that needs `onNewIntent` to actually refresh for a second request.

## Not built yet

- A way to change the port or the wait timeout without editing source.
- `polkit` and lock-screen approval - this project only targets `sudo`
  so far.
- iOS/macOS apps - only Android exists here.
- Automatic reconnect with backoff beyond a fixed 5-second retry.
- Asking for the full-screen alert permission from inside the app
  (Android 14+ does not grant it by default).
- Starting the Android app automatically after a phone reboot (it does
  reconnect on its own after the computer comes back up, as long as
  the app itself is still running).
