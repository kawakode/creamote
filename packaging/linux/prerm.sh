#!/bin/sh
set -e
# Désinstallation (et non mise à jour) : désactive le service utilisateur.
case "$1" in
    remove|purge|0)
        if command -v systemctl >/dev/null 2>&1; then
            systemctl --global disable creamote-host.service >/dev/null 2>&1 || true
        fi
        ;;
esac
