<p align="center">
  <img src="docs/logo.png" alt="approven logo: a fingerprint turning into a checkmark, with Tux" width="260">
</p>

# Approven

Approve `sudo` (and polkit prompts) with your phone's fingerprint, on
one computer or several. An EC P-256 key lives in
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
docs/                   the logo
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

This builds the 3 binaries, installs them to `/usr/local/bin`, adds the
PAM line to `/etc/pam.d/sudo` and `/etc/pam.d/polkit-1` (backing each
up first), sets up the polkit sandbox drop-in described under
[polkit](#polkit), and enables `approved` as your systemd user service.

Optional, and each degrades gracefully when missing: `qrencode` (the
pairing QR code), `avahi` (finding the computer after its IP changes),
`libnotify` (the desktop notification for the app's test button).

Then, on the phone, install the APK from the latest release (or build
your own: `cd android && ./gradlew assembleDebug`) and open it.

Release APKs are signed with a key kept out of this repo (CI reads it
from the `APPROVEN_KEYSTORE_B64` and `APPROVEN_KEYSTORE_PASSWORD`
secrets). Locally, `APPROVEN_KEYSTORE=/path/to/release.keystore` plus
`APPROVEN_KEYSTORE_PASSWORD` sign a release build; without them it
comes out unsigned.

### Pairing

1. On the computer: `sudo approve-cli enroll`. With no phone connected
   yet, it shows a QR code (needs `qrencode`; otherwise it prints the
   same `approven://pair?...` link) and waits.
2. In the app: **Scan QR code**. The code carries the computer's address
   and its certificate fingerprint, so the phone trusts that exact
   computer before it even connects. **Enter the address by hand**
   (LAN IP, port `17165`) works too, trusting the first certificate it
   sees instead.
3. The phone shows a pairing request; approving it asks for a
   fingerprint, then shows a 16-character code.
4. Type that code into the terminal running `enroll`.
5. Test: tap the logo in the app, or run `sudo -k && sudo true`.

On Android 14+, a request only opens on its own with **full-screen
alerts** allowed for Approven; until then the home screen shows a card
that opens that setting. While the app is on screen, requests open
directly either way.

### Several computers

One phone can approve for several computers: run the pairing steps on
each. They share the phone's approval key, and each computer keeps its
own copy of the public half, so forgetting one leaves the others
working. Each computer has its own card on the home screen (status,
disconnect, edit address, forget).

### When the computer's address changes

When a paired computer stops answering at its saved address (the
connection attempt gives up after 5 seconds), the phone looks for it
two ways and moves to whichever answers - the TLS pin still decides
on connect whether it really is that computer:

1. **Plain DNS** on the computer's hostname (the one enrollment
   recorded). Office and campus networks usually register DHCP
   hostnames, and they are exactly the ones that filter multicast.
2. **mDNS**: the daemon announces itself (`_approven._tcp`, through
   `avahi-publish`, with its certificate fingerprint in the TXT
   record), and the phone looks for the fingerprint it pinned. This
   covers home networks, where hostnames often do not resolve.

On a network that offers neither, edit the address in the app. For an
address that never changes, Tailscale works: put the computer's
Tailscale IP in the app with Tailscale running on the phone.

### polkit

`install.sh` also adds the PAM line to `/etc/pam.d/polkit-1`, so the
graphical "authentication required" prompts go through the phone too
(the phone then shows "Allow admin access?" and the `polkit-1`
service instead of a command). polkit 124+ runs its PAM stack in a
sandboxed unit that hides `/run/user`; `install.sh` adds a drop-in,
`/etc/systemd/system/polkit-agent-helper@.service.d/approven.conf`,
that keeps home directories hidden but exposes the daemon's socket
directory, read-only. `uninstall.sh` removes both.

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
- **Pairing by QR code pins the computer up front.** The phone checks
  the computer's certificate against the fingerprint from the code on
  its very first connection.
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

Removes the PAM lines from `sudo` and `polkit-1` (with backups) and the
polkit drop-in, stops the service, removes the binaries. Leaves `/etc/approven` - remove by hand if you want the
enrolled key gone too.

## What's verified and what isn't

Everything in `internal/` and the 3 desktop `cmd/` binaries is tested,
including 2 root-privileged integration tests that actually exercise a
real signature verifying and a tampered one being refused.

The full phone-to-computer path (mutual-TLS pairing, biometric
signing, a full-screen approval prompt reaching the lock screen, the
logo's test sudo, a polkit prompt through `pkexec`) has been exercised
end to end on a real device, including the failure modes that only
show up there: a background service that cannot start an
Activity without a full-screen-intent notification, a notification
permission that has to be requested at runtime on Android 13+, writing
to a socket from a BiometricPrompt callback (the main thread, which
Android forbids for any network I/O), and a `singleInstance` Activity
that needs `onNewIntent` to actually refresh for a second request.
Pairing by QR code, several computers and mDNS rediscovery are covered
by unit tests (`PairingUriTest`, the Go transport and CLI tests); on
the device, only the upgrade of an existing pairing to the
several-computers format has been checked so far.

## Not built yet

- A way to change the port or the wait timeout without editing source.
- Lock-screen (display manager) approval - only `sudo` and polkit.
- iOS/macOS apps - only Android exists here.
- Automatic reconnect with backoff beyond a fixed 5-second retry.
- Starting the Android app automatically after a phone reboot (it does
  reconnect on its own after the computer comes back up, as long as
  the app itself is still running).
