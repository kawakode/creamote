#!/bin/sh
# Construit le paquet d'installation du host pour macOS.
#   packaging/macos/build-pkg.sh <binaire universel> <version> <sortie.pkg>
# Signatures (facultatives) : variables APPLE_SIGNING_IDENTITY (« Developer
# ID Application: … ») et APPLE_INSTALLER_IDENTITY (« Developer ID
# Installer: … »), certificats déjà importés dans le trousseau.
set -eu
bin=$1
version=$2
out=$3
here=$(cd "$(dirname "$0")" && pwd)
root=$(mktemp -d)
dest="$root/Library/Application Support/Creamote"
mkdir -p "$dest"
cp "$bin" "$dest/creamote-host"
chmod 755 "$dest/creamote-host"

if [ -n "${APPLE_SIGNING_IDENTITY:-}" ]; then
    # Runtime renforcé (exigé par la notarisation) ; identifiant stable pour
    # les profils PPPC (Enregistrement de l'écran, Accessibilité).
    codesign --force --timestamp --options runtime \
        --identifier org.creamote.host \
        --sign "$APPLE_SIGNING_IDENTITY" "$dest/creamote-host"
fi

pkgbuild --root "$root" \
    --identifier org.creamote.host.pkg \
    --version "$version" \
    --scripts "$here/scripts" \
    --install-location / \
    "$root.component.pkg"

if [ -n "${APPLE_INSTALLER_IDENTITY:-}" ]; then
    productbuild --package "$root.component.pkg" \
        --sign "$APPLE_INSTALLER_IDENTITY" --timestamp "$out"
else
    productbuild --package "$root.component.pkg" "$out"
fi
rm -rf "$root" "$root.component.pkg"
echo "Paquet : $out"
