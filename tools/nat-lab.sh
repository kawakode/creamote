#!/usr/bin/env bash
# Banc de test du hole punching derrière deux NAT (Linux, root).
#
#   sudo tools/nat-lab.sh cone        # NAT classiques : connexion directe attendue
#   sudo tools/nat-lab.sh symmetric   # NAT symétriques : repli sur le relay attendu
#   sudo tools/nat-lab.sh same-lan    # host et viewer derrière le même NAT :
#                                     # connexion directe par les adresses LAN
#
# Topologie (espaces de noms réseau) :
#
#   host (10.1.0.2) ─ nat1 (203.0.113.11) ─┐
#                                          ├─ inet ─ srv (203.0.113.1:21400)
#   viewer (10.2.0.2) ─ nat2 (203.0.113.12)┘
#
# Les NAT sont des MASQUERADE iptables : correspondance indépendante de la
# destination (« cone ») par défaut, port aléatoire par destination avec
# `symmetric` (--random-fully). Les binaires viennent de target/debug, ou de
# $BIN.
set -euo pipefail

MODE=${1:-cone}
BIN=${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}
WORK=$(mktemp -d)
NS=(cl-inet cl-srv cl-nat1 cl-nat2 cl-host cl-viewer)

cleanup() {
    for ns in "${NS[@]}"; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT
cleanup 2>/dev/null || true
WORK=$(mktemp -d)

for ns in "${NS[@]}"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
x() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# « Internet » : un pont dans cl-inet.
x cl-inet ip link add br0 type bridge
x cl-inet ip link set br0 up
wan() { # ns adresse
    ip link add "w-$1" type veth peer name "p-$1"
    ip link set "w-$1" netns "$1"
    ip link set "p-$1" netns cl-inet
    x cl-inet ip link set "p-$1" master br0 up
    x "$1" ip addr add "$2/24" dev "w-$1"
    x "$1" ip link set "w-$1" up
}
wan cl-srv 203.0.113.1
wan cl-nat1 203.0.113.11
wan cl-nat2 203.0.113.12

lan() { # nat machine réseau
    ip link add "l-$2" type veth peer name "g-$2"
    ip link set "l-$2" netns "$2"
    ip link set "g-$2" netns "$1"
    x "$1" ip addr add "$3.1/24" dev "g-$2"
    x "$1" ip link set "g-$2" up
    x "$2" ip addr add "$3.2/24" dev "l-$2"
    x "$2" ip link set "l-$2" up
    x "$2" ip route add default via "$3.1"
    x "$1" sysctl -qw net.ipv4.ip_forward=1
    local extra=()
    [ "$MODE" = symmetric ] && extra=(--random-fully)
    x "$1" iptables -t nat -C POSTROUTING -o "w-$1" -j MASQUERADE "${extra[@]}" 2>/dev/null && return
    x "$1" iptables -t nat -A POSTROUTING -o "w-$1" -j MASQUERADE "${extra[@]}"
    # Pare-feu de box classique : pas de redirection de port, seul le trafic
    # sortant ouvre le NAT, et le trafic entrant non sollicité est jeté sans
    # créer d'état conntrack (sinon il « empoisonne » la correspondance).
    for chain in INPUT FORWARD; do
        x "$1" iptables -A "$chain" -i "w-$1" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        x "$1" iptables -A "$chain" -i "w-$1" -j DROP
    done
}
lan cl-nat1 cl-host 10.1.0
if [ "$MODE" = same-lan ]; then
    # Le NAT ne fait pas de « hairpinning » : seules les adresses LAN
    # annoncées permettent la connexion directe.
    lan cl-nat1 cl-viewer 10.3.0
else
    lan cl-nat2 cl-viewer 10.2.0
fi

x cl-srv "$BIN/creamote-server" --listen 203.0.113.1:21400 --data-dir "$WORK/srv" \
    >"$WORK/server.log" 2>&1 &
for _ in $(seq 50); do grep -q Empreinte "$WORK/server.log" 2>/dev/null && break; sleep 0.1; done
PIN=$(awk '/Empreinte/ {print $NF}' "$WORK/server.log")

(cd "$WORK" && x cl-host "$BIN/creamote-host" --server 203.0.113.1:21400 --server-pin "$PIN" \
    >"$WORK/host.log" 2>&1) &
for _ in $(seq 50); do grep -q "En ligne" "$WORK/host.log" 2>/dev/null && break; sleep 0.1; done
ID=$(awk -F' : ' '/ID de l.appareil/ {print $2}' "$WORK/host.log")

(printf 'bonjour\n'; sleep 8) | (cd "$WORK" && x cl-viewer "$BIN/creamote-cli" connect "$ID" \
    --server 203.0.113.1:21400 --server-pin "$PIN") >"$WORK/viewer.log" 2>&1 || true

fail() {
    echo "--- viewer ---"; cat "$WORK/viewer.log"
    echo "--- host ---"; cat "$WORK/host.log"
    for n in cl-nat1 cl-nat2; do
        echo "--- conntrack $n ---"
        x "$n" cat /proc/net/nf_conntrack 2>/dev/null | grep udp || true
    done
    echo "ÉCHEC ($MODE) : $1"
    exit 1
}
grep -q "écho : bonjour" "$WORK/viewer.log" || fail "pas d'écho"
case "$MODE" in
    cone | same-lan) want="Connexion directe." ;;
    symmetric) want="Connexion via le relay." ;;
    *) echo "mode inconnu : $MODE"; exit 2 ;;
esac
grep -q "$want" "$WORK/viewer.log" || fail "« $want » attendu"
echo "OK ($MODE) : $want"
