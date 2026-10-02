# Maintainer: bbuddha
pkgname=approven
pkgver=0.1.0.r0.g0000000
pkgrel=1
pkgdesc="Approve sudo with your phone's fingerprint"
arch=('x86_64')
url="https://github.com/bbuddha/approven"
license=('custom')
depends=('glibc' 'pam')
makedepends=('go' 'git')
provides=('approven')
conflicts=('approven')
install="${pkgname}.install"
source=("${pkgname}::git+${url}.git")
sha256sums=('SKIP')

pkgver() {
    cd "$srcdir/$pkgname"
    git describe --long --tags --always | sed 's/^v//; s/-/.r/; s/-/./'
}

build() {
    cd "$srcdir/$pkgname"
    export CGO_ENABLED=0
    go build -trimpath -o approved ./cmd/approved
    go build -trimpath -o approve-helper ./cmd/approve-helper
    go build -trimpath -o approve-cli ./cmd/approve-cli
}

package() {
    cd "$srcdir/$pkgname"
    install -Dm755 approved "$pkgdir/usr/bin/approved"
    install -Dm755 approve-helper "$pkgdir/usr/bin/approve-helper"
    install -Dm755 approve-cli "$pkgdir/usr/bin/approve-cli"
    install -Dm644 dist/approved.service "$pkgdir/usr/lib/systemd/user/approved.service"
    install -Dm644 dist/pam-line.txt "$pkgdir/usr/share/doc/$pkgname/pam-line.txt"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
