#!/bin/sh
# Active le service utilisateur pour toutes les sessions graphiques.
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl --global enable creamote-host.service >/dev/null 2>&1 || true
fi
echo "Creamote host : configurez /etc/creamote/host.conf, il démarrera à la prochaine ouverture de session."
