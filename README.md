# nothing-approve

Approve `sudo` with your phone's fingerprint. Independent implementation
(not a fork) of the feature Flux (bjarneo/flux) calls "approve" -
rebuilt from scratch, same security shape: an EC P-256 key in the
Android Keystore that only signs after a biometric check, a root-owned
trust-anchor file on the computer, and a helper that verifies a
signature it rebuilds itself rather than trusting anything the network
sends back. See `docs/approve.md` in bjarneo/flux for the reference
design this follows.

## What's here

```
internal/protocol/      message format + ECDSA P-256 (shared contract with the phone)
internal/keyfile/       the /etc/nothing-approve/<user>.pub trust anchor, strict checks
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

```sh
go build ./...   # sanity check
sudo ./dist/install.sh
```

This builds the 3 binaries, installs them to `/usr/local/bin`, adds one
line to `/etc/pam.d/sudo`, and enables `approved` as your systemd user
service. It backs up `/etc/pam.d/sudo` before touching it.

Then, on the phone, install `android/app/build/outputs/apk/debug/app-debug.apk`
and open it.

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
binaries. Leaves `/etc/nothing-approve` - remove by hand if you want the
enrolled key gone too.

## What's verified and what isn't

Everything in `internal/` and the 3 desktop `cmd/` binaries is tested,
including 2 root-privileged integration tests that actually exercise a
real signature verifying and a tampered one being refused, and a manual
end-to-end smoke test (real daemon, real CLI, a TLS client standing in
for the phone).

The Android app compiles, passes its own unit tests (the message format
is checked byte-for-byte against the same test vectors the Go side
uses), and lints clean - but the Keystore/BiometricPrompt/foreground
service path has not been exercised on a real device or emulator in
this environment. That path needs a phone to actually confirm before
you rely on it for real `sudo` access: pair it, try a real approval and
a real denial, and try revoking the fingerprint enrollment on the phone
to confirm the key really does stop working (see docs/approve.md's
"Android" section for what that's supposed to do).

## Not built yet

- A way to change the port or the wait timeout without editing source.
- `polkit` and lock-screen approval (docs/approve.md covers both; this
  project only targets `sudo` so far).
- iOS/macOS apps - only Android exists here.
- Automatic reconnect with backoff beyond a fixed 5-second retry.
