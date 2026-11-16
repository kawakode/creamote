#!/usr/bin/env bash
# Banc de test de la capture et de l'injection Wayland, sans compositeur :
# bus D-Bus de session privé, vrai démon PipeWire (+ WirePlumber pour les
# liaisons), source vidéo GStreamer, et faux xdg-desktop-portal servi par
# le test lui-même (crates/creamote-input/tests/portal_lab.rs).
#
#   tools/wayland-lab.sh
#
# Paquets (Debian/Ubuntu) : dbus-daemon pipewire wireplumber
# gstreamer1.0-tools gstreamer1.0-pipewire gstreamer1.0-plugins-base
# libpipewire-0.3-dev clang.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
PIDS=()

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    [ -n "${DBUS_PID:-}" ] && kill "$DBUS_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

export XDG_RUNTIME_DIR=$WORK/run XDG_STATE_HOME=$WORK/state
mkdir -m 700 -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
unset WAYLAND_DISPLAY DISPLAY
export CREAMOTE_LINUX_BACKEND=portal

eval "$(dbus-daemon --session --fork --print-address=1 --print-pid=1 \
    --address="unix:path=$XDG_RUNTIME_DIR/bus" | {
        read -r addr; read -r pid
        echo "export DBUS_SESSION_BUS_ADDRESS=$addr DBUS_PID=$pid"
    })"

pipewire >"$WORK/pipewire.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$XDG_RUNTIME_DIR/pipewire-0" ] && break; sleep 0.1; done
wireplumber >"$WORK/wireplumber.log" 2>&1 & PIDS+=($!)
# Couleur unie connue (BGR e0 50 20), vérifiée par le test.
gst-launch-1.0 -q videotestsrc pattern=solid-color foreground-color=0xff2050e0 is-live=true \
    ! video/x-raw,format=BGRx,width=640,height=360,framerate=30/1 \
    ! pipewiresink mode=provide \
      stream-properties="props,media.class=Video/Source,node.name=creamote-lab" \
    >"$WORK/gst.log" 2>&1 & PIDS+=($!)

NODE=
for _ in $(seq 100); do
    NODE=$(pw-cli ls Node 2>/dev/null | awk '
        /^[[:space:]]*id [0-9]+,/ { id = $2; sub(",", "", id) }
        /node.name = "creamote-lab"/ { print id }')
    [ -n "$NODE" ] && break
    sleep 0.1
done
if [ -z "$NODE" ]; then
    echo "source PipeWire absente" >&2
    tail -n 20 "$WORK"/*.log >&2
    exit 1
fi
echo "source PipeWire : nœud $NODE"
export CREAMOTE_LAB_NODE=$NODE

cd "$ROOT"
cargo test --locked -p creamote-input --features wayland --test portal_lab -- --ignored
