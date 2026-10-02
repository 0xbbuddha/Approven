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
[release](https://github.com/bbuddha/approven/releases/latest) with an
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

### Pairing

1. On the phone, enter the computer's LAN IP and port `17165`, tap Connect.
2. On the computer: `sudo approve-cli enroll`.
3. The phone shows a request; approving it asks for a fingerprint, then
   shows a 16-character code.
4. Type that code into the terminal running `enroll`.
5. Test: `sudo -k && sudo true` - it should ask the phone instead of a password.

`approve-cli status` shows whether the phone is currently connected and
what's enrolled. `sudo approve-cli remove` forgets the phone on the
computer side; "Forget this computer" in the app does the same on the
phone's side.

### Uninstall

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

The full phone-to-computer path (TLS pairing, biometric signing, a
full-screen approval prompt reaching the lock screen) has been
exercised end to end on a real device, including the failure modes
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
- Starting the Android app automatically after a phone reboot (it does
  reconnect on its own after the computer comes back up, as long as
  the app itself is still running).
