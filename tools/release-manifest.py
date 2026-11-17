#!/usr/bin/env python3
"""Manifestes de mise à jour d'une release.

    tools/release-manifest.py <dist> <owner/dépôt> <étiquette> <version>

Écrit dans <dist> :
- host-latest.json : pour chaque paquet du host, URL et empreinte SHA-256
  (le manifeste lui-même est signé ensuite : host-latest.json.sig) ;
- client-latest.json : format « statique » du greffon updater de Tauri, avec
  la signature de chaque paquet (fichiers .sig produits avant l'appel).
"""

import datetime
import glob
import hashlib
import json
import os
import sys


def one(dist, pattern):
    found = sorted(glob.glob(os.path.join(dist, pattern)))
    if len(found) != 1:
        sys.exit(f"{pattern} : {len(found)} fichier(s) trouvé(s), 1 attendu")
    return found[0]


def main():
    dist, repo, tag, version = sys.argv[1:5]
    base = f"https://github.com/{repo}/releases/download/{tag}/"

    def url(path):
        return base + os.path.basename(path)

    def sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    host_assets = {
        "windows-x86_64-msi": f"creamote-host-{version}-x64.msi",
        "darwin-universal-pkg": f"creamote-host-{version}-macos.pkg",
        "linux-x86_64-deb": f"creamote-host_{version}_amd64.deb",
        "linux-x86_64-rpm": f"creamote-host-{version}*.x86_64.rpm",
    }
    host = {"version": version, "assets": {}}
    for kind, pattern in host_assets.items():
        path = one(dist, pattern)
        host["assets"][kind] = {"url": url(path), "sha256": sha256(path)}
    with open(os.path.join(dist, "host-latest.json"), "w") as f:
        json.dump(host, f, indent=2)

    def signed(pattern):
        path = one(dist, pattern)
        with open(path + ".sig") as f:
            return {"signature": f.read().strip(), "url": url(path)}

    mac = signed(f"Creamote_{version}_universal.app.tar.gz")
    client = {
        "version": version,
        "notes": f"Creamote {version}",
        "pub_date": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "platforms": {
            "windows-x86_64": signed(f"Creamote_{version}_x64-setup.exe"),
            "darwin-aarch64": mac,
            "darwin-x86_64": mac,
            "linux-x86_64": signed(f"Creamote_{version}_amd64.AppImage"),
        },
    }
    with open(os.path.join(dist, "client-latest.json"), "w") as f:
        json.dump(client, f, indent=2)


if __name__ == "__main__":
    main()
