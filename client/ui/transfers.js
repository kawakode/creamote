// Liste des transferts de fichiers d'une session : propositions du poste
// distant (accepter / refuser), envois et réceptions en cours (progression,
// annulation), résultats.

export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "";
  const units = ["o", "Kio", "Mio", "Gio", "Tio"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  const digits = i === 0 || n >= 100 ? 0 : 1;
  return `${n.toFixed(digits).replace(".", ",")} ${units[i]}`;
}

// Les identifiants des envois et des réceptions sont indépendants.
const keyOf = (ev) => `${ev.direction}:${ev.id}`;

const STATE_LABEL = {
  offered: "Proposé",
  queued: "En attente du poste distant",
  running: "",
  completed: "Terminé",
  failed: "Échec",
};

export class TransferList {
  // actions : { accept(id), reject(id), cancel(id, direction) }
  constructor(panel, list, actions) {
    this.panel = panel;
    this.list = list;
    this.actions = actions;
    this.items = new Map();
    this.errors = 0;
  }

  handle(ev) {
    if (ev.event === "error") {
      // Échec avant toute proposition (fichier illisible…).
      this.upsert(`error:${++this.errors}`, {
        direction: "send",
        name: ev.name || "fichier",
        state: "failed",
        reason: ev.reason,
      });
      return;
    }
    const key = keyOf(ev);
    const prev = this.items.get(key) || { direction: ev.direction, id: ev.id, done: 0 };
    const t = { ...prev };
    switch (ev.event) {
      case "offered":
        Object.assign(t, { name: ev.name, total: ev.total, state: "offered" });
        break;
      case "queued":
        Object.assign(t, { name: ev.name, total: ev.total, state: t.state || "queued" });
        break;
      case "progress":
        Object.assign(t, { done: ev.done, total: ev.total, state: "running" });
        break;
      case "completed":
        Object.assign(t, { done: t.total ?? t.done, state: "completed", path: ev.path });
        break;
      case "failed":
        Object.assign(t, { state: "failed", reason: ev.reason });
        break;
      default:
        return;
    }
    this.upsert(key, t);
  }

  upsert(key, t) {
    this.items.set(key, t);
    let row = this.list.querySelector(`[data-key="${CSS.escape(key)}"]`);
    if (!row) {
      row = document.createElement("li");
      row.dataset.key = key;
      this.list.prepend(row);
    }
    this.render(row, t);
    this.panel.hidden = false;
  }

  render(row, t) {
    row.className = `transfer ${t.state}`;
    const name = document.createElement("span");
    name.className = "name";
    name.textContent = `${t.direction === "send" ? "↑" : "↓"} ${t.name || `fichier ${t.id}`}`;
    name.title = t.path || t.name || "";

    const meta = document.createElement("span");
    meta.className = "meta";
    const size = t.total !== undefined ? formatBytes(t.total) : "";
    if (t.state === "running") {
      const pct = t.total ? Math.floor((100 * t.done) / t.total) : 0;
      meta.textContent = `${pct} % · ${formatBytes(t.done)} / ${size}`;
    } else if (t.state === "failed") {
      meta.textContent = `${STATE_LABEL.failed} : ${t.reason || ""}`;
    } else {
      meta.textContent = [STATE_LABEL[t.state], size].filter(Boolean).join(" · ");
    }

    const bar = document.createElement("progress");
    bar.max = t.total || 1;
    bar.value = t.state === "completed" ? bar.max : t.done || 0;
    bar.hidden = !(t.state === "running" || t.state === "queued");

    const buttons = document.createElement("span");
    buttons.className = "actions";
    const button = (label, cls, fn) => {
      const b = document.createElement("button");
      b.type = "button";
      b.textContent = label;
      b.className = cls;
      b.addEventListener("click", () => {
        b.disabled = true;
        Promise.resolve(fn()).catch((e) => this.fail(t, String(e)));
      });
      buttons.append(b);
    };
    if (t.state === "offered") {
      button("Accepter", "small", () => {
        this.upsert(keyOf(t), { ...t, state: "running", done: 0 });
        return this.actions.accept(t.id);
      });
      button("Refuser", "small secondary", () => {
        this.upsert(keyOf(t), { ...t, state: "failed", reason: "refusé" });
        return this.actions.reject(t.id);
      });
    } else if ((t.state === "running" || t.state === "queued") && t.id !== undefined) {
      button("Annuler", "small secondary", () => this.actions.cancel(t.id, t.direction));
    }

    row.replaceChildren(name, buttons, meta, bar);
  }

  fail(t, reason) {
    if (t.id === undefined) return;
    this.upsert(keyOf(t), { ...t, state: "failed", reason });
  }

  // Propositions encore sans réponse.
  pending() {
    return [...this.items.values()].filter((t) => t.state === "offered").length;
  }

  clearFinished() {
    for (const [key, t] of this.items) {
      if (t.state === "completed" || t.state === "failed") {
        this.items.delete(key);
        this.list.querySelector(`[data-key="${CSS.escape(key)}"]`)?.remove();
      }
    }
    this.panel.hidden = this.items.size === 0;
  }

  reset() {
    this.items.clear();
    this.list.replaceChildren();
    this.panel.hidden = true;
  }
}
