// Console d'administration Creamote.
//
// Application monopage sans dépendance ni étape de build. Le DOM est construit
// avec `h()` (jamais `innerHTML`), donc les données saisies par les
// utilisateurs ne peuvent pas injecter de HTML. Le jeton d'API est gardé dans
// sessionStorage : il disparaît à la fermeture de l'onglet.

const TOKEN_KEY = "creamote.token";

const PERMISSIONS = [
  ["view_screen", "Voir l'écran"],
  ["control", "Contrôler"],
  ["clipboard", "Presse-papiers"],
  ["file_transfer", "Transfert de fichiers"],
  ["unattended", "Accès sans surveillance"],
  ["manage_devices", "Gérer les machines et parcs"],
  ["manage_access", "Gérer les accès"],
  ["view_audit", "Voir l'audit"],
];
const PERM_LABEL = Object.fromEntries(PERMISSIONS);

const ACTIONS = {
  "auth.login": "Connexion",
  "auth.logout": "Déconnexion",
  "auth.login_failed": "Échec de connexion",
  "auth.totp_enable": "Double authentification activée",
  "auth.totp_disable": "Double authentification désactivée",
  "auth.totp_reset": "Double authentification réinitialisée",
  "auth.recovery_code_used": "Code de secours utilisé",
  "auth.oidc_link": "Compte lié au SSO",
  "user.create": "Utilisateur créé",
  "entity.create": "Entité créée",
  "entity.delete": "Entité supprimée",
  "member.add": "Membre ajouté",
  "member.remove": "Membre retiré",
  "fleet.create": "Parc créé",
  "fleet.update": "Parc modifié",
  "fleet.delete": "Parc supprimé",
  "group.create": "Groupe créé",
  "group.delete": "Groupe supprimé",
  "group.member.add": "Ajout à un groupe",
  "group.member.remove": "Retrait d'un groupe",
  "role.create": "Rôle créé",
  "role.delete": "Rôle supprimé",
  "binding.create": "Attribution créée",
  "binding.delete": "Attribution supprimée",
  "enrollment_token.create": "Jeton d'enrôlement créé",
  "enrollment_token.delete": "Jeton d'enrôlement révoqué",
  "device.enroll": "Machine enrôlée",
  "device.update": "Machine modifiée",
  "device.delete": "Machine retirée",
  "ticket.issue": "Ticket de session émis",
};

// ------------------------------------------------------------------ outils

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

const storage = {
  get() {
    try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  set(v) {
    try { v ? sessionStorage.setItem(TOKEN_KEY, v) : sessionStorage.removeItem(TOKEN_KEY); } catch { /* navigation privée */ }
  },
};

class ApiError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(method, path, body) {
  const headers = { Accept: "application/json" };
  const token = storage.get();
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const resp = await fetch(`/api/v1${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "omit",
    cache: "no-store",
  });
  if (resp.status === 401 && path !== "/auth/login") {
    storage.set(null);
    state.me = null;
    location.hash = "#/login";
    throw new ApiError(401, "Session expirée, reconnectez-vous.");
  }
  const text = await resp.text();
  const data = text ? JSON.parse(text) : null;
  if (!resp.ok) throw new ApiError(resp.status, capitalize(data?.message || `erreur ${resp.status}`), data?.error);
  return data;
}

function capitalize(m) {
  return m.charAt(0).toUpperCase() + m.slice(1) + (/[.!?]$/.test(m) ? "" : ".");
}

const get = (p) => api("GET", p);
const post = (p, b) => api("POST", p, b ?? {});
const patch = (p, b) => api("PATCH", p, b);
const del = (p) => api("DELETE", p);

function fmtDate(secs) {
  if (!secs) return "—";
  return new Date(secs * 1000).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" });
}

function ago(secs) {
  if (!secs) return "jamais";
  const d = Math.max(0, Date.now() / 1000 - secs);
  if (d < 90) return "à l'instant";
  if (d < 3600) return `il y a ${Math.round(d / 60)} min`;
  if (d < 86400) return `il y a ${Math.round(d / 3600)} h`;
  return `il y a ${Math.round(d / 86400)} j`;
}

function permPills(perms) {
  if (!perms?.length) return h("span", { class: "muted" }, "aucune");
  return perms.map((p) => h("span", { class: "pill", title: p }, PERM_LABEL[p] || p));
}

function table(headers, rows, empty) {
  if (!rows.length) return h("p", { class: "empty" }, empty);
  return h("div", { class: "table-wrap" },
    h("table", {},
      h("thead", {}, h("tr", {}, headers.map((x) => h("th", {}, x)))),
      h("tbody", {}, rows.map((r) => h("tr", {}, r.map((c) => (c instanceof Node && c.tagName === "TD" ? c : h("td", {}, c))))))));
}

function select(name, options, attrs = {}) {
  return h("select", { name, ...attrs },
    options.map(([v, label]) => h("option", { value: v }, label)));
}

/// Bouton de suppression en deux temps (pas de boîte de dialogue bloquante).
function dangerButton(label, action) {
  const b = h("button", { class: "danger", type: "button" }, label);
  let armed = false;
  let timer;
  b.addEventListener("click", async () => {
    if (!armed) {
      armed = true;
      b.classList.add("confirm");
      b.textContent = "Confirmer";
      timer = setTimeout(() => { armed = false; b.classList.remove("confirm"); b.textContent = label; }, 4000);
      return;
    }
    clearTimeout(timer);
    b.disabled = true;
    await run(action);
  });
  return b;
}

/// Exécute une action ; recharge la vue si elle réussit, affiche l'erreur sinon.
async function run(action, { reload = true } = {}) {
  try {
    const r = await action();
    if (reload) await render();
    return r;
  } catch (e) {
    flash(e.message, "error");
    return undefined;
  }
}

let pendingFlash = null;
function flash(message, kind = "info") {
  pendingFlash = { message, kind };
  const slot = document.getElementById("flash");
  if (slot) {
    slot.replaceChildren(h("div", { class: `banner ${kind}`, role: kind === "error" ? "alert" : "status" }, message));
    if (kind === "error") pendingFlash = null;
  }
}

function formData(form) {
  return Object.fromEntries(new FormData(form).entries());
}

function onSubmit(handler) {
  return async (ev) => {
    ev.preventDefault();
    const form = ev.currentTarget;
    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try {
      await handler(formData(form), form);
    } catch (e) {
      flash(e.message, "error");
    } finally {
      if (btn) btn.disabled = false;
    }
  };
}

// ------------------------------------------------------------------ état

const state = { me: null };

async function loadMe() {
  state.me = await get("/me");
  return state.me;
}

function route() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  return parts;
}

// ------------------------------------------------------------------ vues

function loginView() {
  const codeField = h("label", { hidden: true }, "Code de l'application d'authentification (ou code de secours)",
    h("input", { name: "totp_code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 12 }));
  const form = h("form", { class: "stack card", onsubmit: onSubmit(async (d) => {
    const body = { email: d.email, password: d.password };
    if (!codeField.hidden) body.totp_code = d.totp_code;
    let r;
    try {
      r = await api("POST", "/auth/login", body);
    } catch (e) {
      if (e.code === "totp_required") {
        codeField.hidden = false;
        codeField.querySelector("input").focus();
        flash("Saisissez le code de votre application d'authentification.", "info");
        return;
      }
      if (e.code === "totp_invalid") throw new Error("Code incorrect.");
      if (e.status === 401) throw new Error("E-mail ou mot de passe incorrect.");
      throw e;
    }
    storage.set(r.token);
    await loadMe();
    location.hash = "#/";
  }) },
    h("label", {}, "E-mail", h("input", { name: "email", type: "email", required: true, autocomplete: "username", autofocus: true })),
    h("label", {}, "Mot de passe", h("input", { name: "password", type: "password", required: true, autocomplete: "current-password" })),
    codeField,
    h("button", { class: "primary", type: "submit" }, "Se connecter"));
  const sso = h("div", { class: "sso" });
  // Bouton SSO si le serveur propose OIDC.
  fetch("/api/v1/auth/methods", { credentials: "omit", cache: "no-store" })
    .then((r) => (r.ok ? r.json() : null))
    .then((m) => {
      if (!m?.oidc) return;
      sso.replaceChildren(
        h("button", { type: "button", class: "primary sso-button", onclick: () => { location.href = "/api/v1/auth/oidc/start"; } },
          `Se connecter avec ${m.oidc.name}`),
        h("p", { class: "muted small or" }, "ou avec un mot de passe"));
    })
    .catch(() => {});
  return h("main", { class: "login" },
    h("h1", {}, "Creamote"),
    h("p", { class: "muted" }, "Console d'administration"),
    h("div", { id: "flash" }),
    sso,
    form);
}

const OIDC_ERRORS = {
  no_account: "Aucun compte Creamote ne correspond à cette identité. Demandez à un administrateur de créer votre compte avec la même adresse e-mail.",
  unverified: "Votre fournisseur d'identité n'a pas confirmé votre adresse e-mail.",
  conflict: "Ce compte Creamote est déjà lié à une autre identité. Contactez un administrateur.",
  disabled: "Ce compte est désactivé.",
  denied: "Connexion annulée ou refusée par le fournisseur d'identité.",
  state: "La connexion a expiré. Réessayez.",
  token: "La réponse du fournisseur d'identité est invalide. Contactez un administrateur.",
  provider: "Le fournisseur d'identité est injoignable. Réessayez plus tard.",
};

/// Retour du SSO : échange du code à usage unique contre un jeton d'API.
async function finishOidc(code) {
  history.replaceState(null, "", "#/login");
  try {
    const r = await api("POST", "/auth/oidc/exchange", { code });
    storage.set(r.token);
    state.me = null;
    location.hash = "#/";
  } catch {
    app().replaceChildren(loginView());
    flash(OIDC_ERRORS.state, "error");
  }
}

function shell(content) {
  const me = state.me;
  return [
    h("header", { class: "top" },
      h("a", { class: "brand", href: "#/" }, h("img", { src: "icon.svg", alt: "" }), "Creamote"),
      h("nav", {},
        h("a", { href: "#/" }, "Entités"),
        h("a", { href: "#/book" }, "Carnet d'adresses"),
        me.user.is_superadmin ? h("a", { href: "#/users" }, "Utilisateurs") : null),
      h("a", { class: "who", href: "#/account", title: "Mon compte" }, me.user.display_name, " · ", me.user.email,
        me.totp_enabled ? null : h("span", { class: "pill warn", title: "Double authentification inactive" }, "2FA")),
      h("button", { type: "button", class: "link", onclick: async () => {
        try { await post("/auth/logout"); } catch { /* jeton déjà expiré */ }
        storage.set(null);
        state.me = null;
        location.hash = "#/login";
      } }, "Déconnexion")),
    h("main", {}, h("div", { id: "flash" }), content),
  ];
}

async function entitiesView() {
  const me = await loadMe();
  const rows = me.entities.map((e) => [
    h("a", { href: `#/e/${encodeURIComponent(e.id)}/devices` }, e.name),
    permPills(e.permissions),
    me.user.is_superadmin
      ? h("td", { class: "actions" }, dangerButton("Supprimer", () => del(`/entities/${e.id}`)))
      : "",
  ]);
  return [
    h("h1", {}, "Entités"),
    table(["Nom", "Vos permissions (niveau entité)", ""], rows,
      "Vous n'êtes membre d'aucune entité. Un super-administrateur doit vous y ajouter."),
    me.user.is_superadmin ? [
      h("h2", {}, "Nouvelle entité"),
      h("form", { class: "inline card", onsubmit: onSubmit(async (d, f) => {
        await post("/entities", { name: d.name, owner_email: d.owner_email || null });
        f.reset();
        flash("Entité créée.");
        await render();
      }) },
        h("label", {}, "Nom", h("input", { name: "name", required: true, maxlength: 200 })),
        h("label", {}, "E-mail du propriétaire (facultatif)", h("input", { name: "owner_email", type: "email" })),
        h("button", { class: "primary", type: "submit" }, "Créer")),
    ] : null,
  ];
}

async function usersView() {
  if (!state.me.user.is_superadmin) return h("p", {}, "Réservé aux super-administrateurs.");
  const users = await get("/users");
  return [
    h("h1", {}, "Utilisateurs"),
    table(["E-mail", "Nom", "Rôle", "État", "Double authentification", ""], users.map((u) => [
      u.email, u.display_name,
      u.is_superadmin ? h("span", { class: "pill" }, "super-admin") : "",
      u.disabled ? "désactivé" : "actif",
      h("span", {}, u.totp_enabled ? "active" : h("span", { class: "muted" }, "inactive"), u.sso_linked ? h("span", { class: "pill" }, "SSO") : null),
      u.totp_enabled && u.id !== state.me.user.id
        ? h("td", { class: "actions" }, dangerButton("Réinitialiser la 2FA", async () => {
          await post(`/users/${u.id}/totp/reset`);
          flash(`Double authentification de ${u.email} désactivée et sessions révoquées.`);
        }))
        : "",
    ]), "Aucun utilisateur."),
    h("h2", {}, "Nouvel utilisateur"),
    h("form", { class: "inline card", onsubmit: onSubmit(async (d, f) => {
      await post("/users", {
        email: d.email, display_name: d.display_name, password: d.password,
        superadmin: d.superadmin === "on",
      });
      f.reset();
      flash("Utilisateur créé. Transmettez-lui son mot de passe par un canal sûr.");
      await render();
    }) },
      h("label", {}, "E-mail", h("input", { name: "email", type: "email", required: true })),
      h("label", {}, "Nom affiché", h("input", { name: "display_name", required: true, maxlength: 200 })),
      h("label", {}, "Mot de passe (12 caractères min.)", h("input", { name: "password", type: "password", required: true, minlength: 12, autocomplete: "new-password" })),
      h("label", { class: "check" }, h("input", { name: "superadmin", type: "checkbox" }), "Super-administrateur"),
      h("button", { class: "primary", type: "submit" }, "Créer")),
  ];
}

async function accountView() {
  const me = await loadMe();
  const content = [h("h1", {}, "Mon compte"),
    h("p", {}, me.user.display_name, " · ", me.user.email),
    h("h2", {}, "Double authentification")];
  if (me.totp_enabled) {
    content.push(
      h("p", {}, "Active. Codes de secours restants : ", h("strong", {}, me.recovery_codes_left), "."),
      me.recovery_codes_left < 3
        ? h("div", { class: "banner error" }, "Il vous reste peu de codes de secours : désactivez puis réactivez la double authentification pour en obtenir de nouveaux.")
        : null,
      h("form", { class: "inline card", onsubmit: onSubmit(async (d) => {
        await post("/me/totp/disable", { password: d.password, code: d.code });
        flash("Double authentification désactivée.");
        await render();
      }) },
        h("label", {}, "Mot de passe", h("input", { name: "password", type: "password", required: true, autocomplete: "current-password" })),
        h("label", {}, "Code actuel ou code de secours", h("input", { name: "code", required: true, autocomplete: "one-time-code" })),
        h("button", { class: "danger", type: "submit" }, "Désactiver")));
    return content;
  }
  const step = h("div", {});
  content.push(
    h("p", { class: "muted" }, "Protégez votre compte avec un code à 6 chiffres généré par une application d'authentification (Aegis, FreeOTP, Google Authenticator, 1Password…)."),
    step);
  step.append(h("form", { class: "inline card", onsubmit: onSubmit(async (d) => {
    const s = await post("/me/totp/setup", { password: d.password });
    const qr = s.qr_svg ? URL.createObjectURL(new Blob([s.qr_svg], { type: "image/svg+xml" })) : null;
    step.replaceChildren(h("div", { class: "card" },
      h("p", {}, "1. Scannez ce QR code avec votre application, ou saisissez la clé à la main."),
      qr ? h("img", { src: qr, alt: "QR code de configuration", class: "qr", width: 200, height: 200 }) : null,
      h("p", {}, "Clé : ", h("code", { class: "secret" }, s.secret.match(/.{1,4}/g).join(" "))),
      h("p", {}, "2. Saisissez le code affiché pour confirmer."),
      h("form", { class: "inline", onsubmit: onSubmit(async (x) => {
        const r = await post("/me/totp/enable", { code: x.code });
        if (qr) URL.revokeObjectURL(qr);
        state.me = null;
        step.replaceChildren(h("div", { class: "card" },
          h("div", { class: "banner info", role: "status" }, "Double authentification active."),
          h("p", {}, "Codes de secours : chacun ne sert qu'une fois, si vous perdez votre téléphone. Ils ne seront plus affichés : conservez-les en lieu sûr."),
          h("pre", { class: "codes" }, r.recovery_codes.join("\n")),
          h("button", { type: "button", class: "primary", onclick: () => render() }, "J'ai noté mes codes")));
      }) },
        h("label", {}, "Code", h("input", { name: "code", required: true, inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, autofocus: true })),
        h("button", { class: "primary", type: "submit" }, "Activer"))));
  }) },
    h("label", {}, "Confirmez votre mot de passe", h("input", { name: "password", type: "password", required: true, autocomplete: "current-password" })),
    h("button", { class: "primary", type: "submit" }, "Configurer")));
  return content;
}

async function bookView() {
  const entries = await get("/me/address-book");
  const rows = entries.map((e) => {
    const cell = h("td", {}, h("strong", {}, e.label), e.notes ? h("div", { class: "muted small" }, e.notes) : null);
    return [
      cell,
      h("td", { class: "nowrap" }, h("code", {}, e.device_id)),
      h("td", { class: "actions" },
        h("button", { type: "button", onclick: () => {
          cell.replaceChildren(h("form", { class: "inline", onsubmit: onSubmit(async (d) => {
            await patch(`/me/address-book/${e.id}`, { label: d.label, notes: d.notes });
            await render();
          }) },
            h("input", { name: "label", value: e.label, required: true, maxlength: 200, "aria-label": "Nom" }),
            h("input", { name: "notes", value: e.notes, maxlength: 2000, "aria-label": "Notes" }),
            h("button", { class: "primary", type: "submit" }, "Enregistrer")));
        } }, "Modifier"),
        " ",
        dangerButton("Supprimer", () => del(`/me/address-book/${e.id}`))),
    ];
  });
  return [
    h("h1", {}, "Carnet d'adresses"),
    h("p", { class: "muted" }, "Vos machines hors parc, par leur ID. Personne d'autre ne voit ce carnet."),
    table(["Machine", "ID", ""], rows, "Carnet vide."),
    h("h2", {}, "Ajouter"),
    h("form", { class: "inline card", onsubmit: onSubmit(async (d, f) => {
      await post("/me/address-book", { label: d.label, device_id: d.device_id, notes: d.notes });
      f.reset();
      await render();
    }) },
      h("label", {}, "Nom", h("input", { name: "label", required: true, maxlength: 200 })),
      h("label", {}, "ID (9 chiffres)", h("input", { name: "device_id", required: true, inputmode: "numeric", pattern: "[0-9 ]{9,11}", placeholder: "123 456 789" })),
      h("label", {}, "Notes", h("input", { name: "notes", maxlength: 2000 })),
      h("button", { class: "primary", type: "submit" }, "Ajouter")),
  ];
}

// ------------------------------------------------------------- une entité

const TABS = [
  ["devices", "Machines"],
  ["fleets", "Parcs"],
  ["members", "Membres"],
  ["groups", "Groupes"],
  ["roles", "Rôles"],
  ["bindings", "Attributions"],
  ["audit", "Audit"],
];

/// Parcs triés en arbre : [{ fleet, depth }].
function fleetTree(fleets) {
  const children = new Map();
  for (const f of fleets) {
    const k = f.parent_id || "";
    if (!children.has(k)) children.set(k, []);
    children.get(k).push(f);
  }
  const out = [];
  const walk = (parent, depth) => {
    for (const f of (children.get(parent) || []).sort((a, b) => a.name.localeCompare(b.name))) {
      out.push({ fleet: f, depth });
      walk(f.id, depth + 1);
    }
  };
  walk("", 0);
  return out;
}

function fleetOptions(fleets, { root } = {}) {
  const opts = fleetTree(fleets).map(({ fleet, depth }) => [fleet.id, `${"  ".repeat(depth)}${depth ? "└ " : ""}${fleet.name}`]);
  return root ? [["", root], ...opts] : opts;
}

/// Parcs que l'utilisateur peut gérer (manage_devices), pour n'afficher que
/// les actions qu'il a le droit de faire. Le serveur reste seul juge.
async function manageableFleets({ base, can }, fleets) {
  if (can("manage_devices")) return new Set(fleets.map((f) => f.id));
  const perms = await Promise.all(fleets.map((f) =>
    get(`${base}/my-permissions?fleet_id=${encodeURIComponent(f.id)}`).then((r) => [f.id, r.permissions])));
  return new Set(perms.filter(([, p]) => p.includes("manage_devices")).map(([id]) => id));
}

async function entityView(eid, tab) {
  const ent = state.me.entities.find((e) => e.id === eid) || (await loadMe()).entities.find((e) => e.id === eid);
  if (!ent) return [h("h1", {}, "Entité introuvable"), h("p", {}, h("a", { href: "#/" }, "Retour aux entités"))];
  const base = `/entities/${encodeURIComponent(eid)}`;
  const can = (p) => ent.permissions.includes(p);
  const ctx = { eid, base, can, ent };
  const views = { devices: devicesTab, fleets: fleetsTab, members: membersTab, groups: groupsTab, roles: rolesTab, bindings: bindingsTab, audit: auditTab };
  const view = views[tab] || devicesTab;
  return [
    h("h1", {}, ent.name),
    h("nav", { class: "tabs" }, TABS
      .filter(([k]) => k !== "audit" || can("view_audit"))
      .map(([k, label]) => h("a", { href: `#/e/${encodeURIComponent(eid)}/${k}`, class: k === (views[tab] ? tab : "devices") ? "active" : "" }, label))),
    await view(ctx),
  ];
}

async function devicesTab(ctx) {
  const { base } = ctx;
  const [devices, fleets, tokens, info] = await Promise.all([
    get(`${base}/devices`), get(`${base}/fleets`),
    get(`${base}/enrollment-tokens`), get("/server-info"),
  ]);
  const managed = await manageableFleets(ctx, fleets);
  const managedFleets = fleets.filter((f) => managed.has(f.id));
  const fleetName = Object.fromEntries(fleets.map((f) => [f.id, f.name]));
  const rows = devices.map((d) => {
    const manage = d.permissions.includes("manage_devices");
    const nameCell = h("td", {}, h("strong", {}, d.name), h("div", { class: "muted small" }, d.platform));
    const actions = h("td", { class: "actions" });
    if (manage) {
      actions.append(
        h("button", { type: "button", onclick: () => {
          nameCell.replaceChildren(h("form", { class: "inline", onsubmit: onSubmit(async (x) => {
            await patch(`${base}/devices/${d.id}`, { name: x.name, fleet_id: x.fleet_id });
            flash("Machine modifiée.");
            await render();
          }) },
            h("input", { name: "name", value: d.name, required: true, maxlength: 200, "aria-label": "Nom" }),
            (() => { const s = select("fleet_id", fleetOptions(fleets).filter(([id]) => managed.has(id)), { "aria-label": "Parc" }); s.value = d.fleet_id; return s; })(),
            h("button", { class: "primary", type: "submit" }, "Enregistrer")));
        } }, "Modifier"),
        " ",
        dangerButton("Retirer", () => del(`${base}/devices/${d.id}`)));
    }
    return [
      nameCell,
      h("td", { class: "nowrap" }, h("code", {}, d.device_id)),
      fleetName[d.fleet_id] || "—",
      h("td", { class: "nowrap" }, h("span", { class: `dot ${d.online ? "on" : ""}` }), d.online ? "en ligne" : ago(d.last_seen)),
      permPills(d.permissions),
      actions,
    ];
  });

  const server = info.server_address || "<adresse-du-serveur>:21400";
  return [
    table(["Machine", "ID", "Parc", "État", "Vos permissions", ""], rows,
      "Aucune machine visible. Enrôlez-en une avec un jeton ci-dessous."),
    managedFleets.length === 0
      ? (ctx.can("manage_devices") ? [h("h2", {}, "Enrôler des machines"), h("p", { class: "empty" }, "Créez d'abord un parc (onglet Parcs).")] : null)
      : [h("h2", {}, "Enrôler des machines"), h("div", { class: "card" },
        h("form", { class: "inline", onsubmit: onSubmit(async (d) => {
          const t = await post(`${base}/enrollment-tokens`, {
            fleet_id: d.fleet_id, uses: Number(d.uses), ttl_hours: Number(d.ttl_hours),
          });
          const cmd = `creamote-host --server ${server} --server-pin ${info.server_pin} --enroll ${t.token} --name "<nom de la machine>"`;
          await render();
          const slot = document.getElementById("new-token");
          slot?.replaceChildren(
            h("div", { class: "banner info", role: "status" },
              "Jeton créé. Il ne sera plus affiché : copiez la commande maintenant."),
            h("pre", {}, cmd));
        }) },
          h("label", {}, "Parc", select("fleet_id", fleetOptions(fleets).filter(([id]) => managed.has(id)))),
          h("label", {}, "Machines", h("input", { name: "uses", type: "number", min: 1, max: 1000, value: 1 })),
          h("label", {}, "Validité (heures)", h("input", { name: "ttl_hours", type: "number", min: 1, max: 720, value: 24 })),
          h("button", { class: "primary", type: "submit" }, "Créer un jeton")),
        h("div", { id: "new-token" }),
        h("p", { class: "muted small" },
          "Sur la machine, la commande enrôle le host dans le parc. Il n'accepte ensuite que les sessions autorisées par ticket."))],
    tokens.length ? [
      h("h2", {}, "Jetons actifs"),
      table(["Parc", "Machines restantes", "Créé", "Expire", ""], tokens.map((t) => [
        fleetName[t.fleet_id] || "—", t.uses_left, fmtDate(t.created_at), fmtDate(t.expires_at),
        h("td", { class: "actions" }, dangerButton("Révoquer", () => del(`${base}/enrollment-tokens/${t.id}`))),
      ]), ""),
    ] : null,
  ];
}

async function fleetsTab(ctx) {
  const { base, can } = ctx;
  const fleets = await get(`${base}/fleets`);
  const managed = await manageableFleets(ctx, fleets);
  const parents = fleetOptions(fleets, { root: "(racine)" })
    .filter(([id]) => (id ? managed.has(id) : can("manage_devices")));
  const rows = fleetTree(fleets).map(({ fleet: f, depth }) => {
    const nameCell = h("td", {}, h("span", { class: "tree-indent" }, "    ".repeat(depth), depth ? "└ " : ""), f.name);
    return [
      nameCell,
      !managed.has(f.id) ? "" : h("td", { class: "actions" },
        h("button", { type: "button", onclick: () => {
          const s = select("parent_id", parents.filter(([id]) => id !== f.id), { "aria-label": "Parent" });
          s.value = f.parent_id || "";
          nameCell.replaceChildren(h("form", { class: "inline", onsubmit: onSubmit(async (d) => {
            await patch(`${base}/fleets/${f.id}`, { name: d.name, parent_id: d.parent_id || null });
            flash("Parc modifié.");
            await render();
          }) },
            h("input", { name: "name", value: f.name, required: true, maxlength: 200, "aria-label": "Nom" }), s,
            h("button", { class: "primary", type: "submit" }, "Enregistrer")));
        } }, "Modifier"),
        " ",
        dangerButton("Supprimer", () => del(`${base}/fleets/${f.id}`))),
    ];
  });
  return [
    table(["Parc", ""], rows, "Aucun parc."),
    parents.length === 0 ? null : h("h2", {}, "Nouveau parc"),
    parents.length === 0 ? null : h("form", { class: "inline card", onsubmit: onSubmit(async (d, f) => {
      await post(`${base}/fleets`, { name: d.name, parent_id: d.parent_id || null });
      f.reset();
      flash("Parc créé.");
      await render();
    }) },
      h("label", {}, "Nom", h("input", { name: "name", required: true, maxlength: 200 })),
      h("label", {}, "Dans", select("parent_id", parents)),
      h("button", { class: "primary", type: "submit" }, "Créer")),
  ];
}

async function membersTab({ base, can }) {
  const members = await get(`${base}/members`);
  return [
    table(["E-mail", "Nom", ""], members.map((m) => [
      m.email, m.display_name,
      can("manage_access") ? h("td", { class: "actions" }, dangerButton("Retirer", () => del(`${base}/members/${m.user_id}`))) : "",
    ]), "Aucun membre."),
    can("manage_access") ? [
      h("h2", {}, "Ajouter un membre"),
      h("form", { class: "inline card", onsubmit: onSubmit(async (d, f) => {
        await post(`${base}/members`, { email: d.email });
        f.reset();
        flash("Membre ajouté. Donnez-lui un rôle dans l'onglet Attributions.");
        await render();
      }) },
        h("label", {}, "E-mail d'un utilisateur existant", h("input", { name: "email", type: "email", required: true })),
        h("button", { class: "primary", type: "submit" }, "Ajouter")),
    ] : null,
  ];
}

async function groupsTab({ eid, base, can }) {
  const [groups, members] = await Promise.all([get(`${base}/groups`), get(`${base}/members`)]);
  const selected = route()[3];
  const group = groups.find((g) => g.id === selected) || groups[0];
  let detail = h("p", { class: "empty" }, "Aucun groupe.");
  if (group) {
    const gm = await get(`${base}/groups/${group.id}/members`);
    const inGroup = new Set(gm.map((m) => m.user_id));
    const candidates = members.filter((m) => !inGroup.has(m.user_id));
    detail = h("div", {},
      h("h2", {}, group.name),
      table(["E-mail", "Nom", ""], gm.map((m) => [
        m.email, m.display_name,
        can("manage_access") ? h("td", { class: "actions" }, dangerButton("Retirer", () => del(`${base}/groups/${group.id}/members/${m.user_id}`))) : "",
      ]), "Groupe vide."),
      can("manage_access") && candidates.length ? h("form", { class: "inline card", onsubmit: onSubmit(async (d) => {
        await post(`${base}/groups/${group.id}/members`, { user_id: d.user_id });
        await render();
      }) },
        h("label", {}, "Ajouter", select("user_id", candidates.map((m) => [m.user_id, `${m.display_name} (${m.email})`]))),
        h("button", { class: "primary", type: "submit" }, "Ajouter")) : null,
      can("manage_access") ? h("p", {}, dangerButton("Supprimer le groupe", () => del(`${base}/groups/${group.id}`))) : null);
  }
  return [
    h("div", { class: "grid2" },
      h("div", {},
        h("div", { class: "list-select card" }, groups.length
          ? groups.map((g) => h("a", { href: `#/e/${encodeURIComponent(eid)}/groups/${g.id}`, class: g === group ? "active" : "" }, g.name))
          : h("span", { class: "muted" }, "Aucun groupe")),
        can("manage_access") ? h("form", { class: "stack card", onsubmit: onSubmit(async (d, f) => {
          const r = await post(`${base}/groups`, { name: d.name });
          f.reset();
          location.hash = `#/e/${encodeURIComponent(eid)}/groups/${r.id}`;
        }) },
          h("label", {}, "Nouveau groupe", h("input", { name: "name", required: true, maxlength: 200 })),
          h("button", { class: "primary", type: "submit" }, "Créer")) : null),
      detail),
  ];
}

async function rolesTab({ base, can }) {
  const roles = await get(`${base}/roles`);
  return [
    table(["Rôle", "Permissions", ""], roles.map((r) => [
      h("td", {}, h("strong", {}, r.name), r.builtin ? h("div", { class: "muted small" }, "intégré") : null),
      permPills(r.permissions),
      !r.builtin && can("manage_access") ? h("td", { class: "actions" }, dangerButton("Supprimer", () => del(`${base}/roles/${r.id}`))) : "",
    ]), "Aucun rôle."),
    can("manage_access") ? [
      h("h2", {}, "Nouveau rôle"),
      h("form", { class: "stack card", onsubmit: onSubmit(async (d, f) => {
        const permissions = PERMISSIONS.map(([k]) => k).filter((k) => d[`p_${k}`] === "on");
        await post(`${base}/roles`, { name: d.name, permissions });
        f.reset();
        flash("Rôle créé.");
        await render();
      }) },
        h("label", {}, "Nom", h("input", { name: "name", required: true, maxlength: 200 })),
        h("div", { class: "perms" }, PERMISSIONS.map(([k, label]) =>
          h("label", { class: "check" }, h("input", { type: "checkbox", name: `p_${k}` }), label))),
        h("div", {}, h("button", { class: "primary", type: "submit" }, "Créer"))),
    ] : null,
  ];
}

async function bindingsTab({ base, can }) {
  const [bindings, roles, members, groups, fleets, devices] = await Promise.all([
    get(`${base}/bindings`), get(`${base}/roles`), get(`${base}/members`),
    get(`${base}/groups`), get(`${base}/fleets`), get(`${base}/devices`),
  ]);
  const names = {
    role: Object.fromEntries(roles.map((r) => [r.id, r.name])),
    user: Object.fromEntries(members.map((m) => [m.user_id, m.email])),
    group: Object.fromEntries(groups.map((g) => [g.id, g.name])),
    fleet: Object.fromEntries(fleets.map((f) => [f.id, f.name])),
    device: Object.fromEntries(devices.map((d) => [d.id, `${d.name} (${d.device_id})`])),
  };
  const KIND = { user: "Utilisateur", group: "Groupe", entity: "Toute l'entité", fleet: "Parc", device: "Machine" };
  const ref = (r) => r.kind === "entity" ? KIND.entity : h("span", {}, h("span", { class: "muted" }, `${KIND[r.kind] || r.kind} `), names[r.kind]?.[r.id] || h("code", {}, r.id));

  const subjectSel = select("subject", [
    ...members.map((m) => [`user:${m.user_id}`, `Utilisateur · ${m.display_name} (${m.email})`]),
    ...groups.map((g) => [`group:${g.id}`, `Groupe · ${g.name}`]),
  ]);
  const scopeSel = select("scope", [
    ["entity:", "Toute l'entité"],
    ...fleetTree(fleets).map(({ fleet, depth }) => [`fleet:${fleet.id}`, `Parc · ${"  ".repeat(depth)}${fleet.name}`]),
    ...devices.map((d) => [`device:${d.id}`, `Machine · ${d.name} (${d.device_id})`]),
  ]);
  const split = (v) => { const i = v.indexOf(":"); return { kind: v.slice(0, i), id: v.slice(i + 1) }; };

  return [
    table(["Rôle", "Pour", "Sur", ""], bindings.map((b) => [
      names.role[b.role_id] || b.role_id, ref(b.subject), ref(b.scope),
      can("manage_access") ? h("td", { class: "actions" }, dangerButton("Retirer", () => del(`${base}/bindings/${b.id}`))) : "",
    ]), "Aucune attribution."),
    can("manage_access") ? [
      h("h2", {}, "Nouvelle attribution"),
      members.length + groups.length === 0
        ? h("p", { class: "empty" }, "Ajoutez d'abord des membres ou des groupes.")
        : h("form", { class: "inline card", onsubmit: onSubmit(async (d) => {
          await post(`${base}/bindings`, { role_id: d.role_id, subject: split(d.subject), scope: split(d.scope) });
          flash("Attribution créée.");
          await render();
        }) },
          h("label", {}, "Rôle", select("role_id", roles.map((r) => [r.id, r.name]))),
          h("label", {}, "Pour", subjectSel),
          h("label", {}, "Sur", scopeSel),
          h("button", { class: "primary", type: "submit" }, "Attribuer")),
      h("p", { class: "muted small" }, "Une attribution sur un parc vaut pour ses sous-parcs et leurs machines."),
    ] : null,
  ];
}

async function auditTab({ base }) {
  const [entries, members] = await Promise.all([get(`${base}/audit?limit=200`), get(`${base}/members`)]);
  const who = Object.fromEntries(members.map((m) => [m.user_id, m.email]));
  return table(["Date", "Auteur", "Action", "Détail"], entries.map((a) => [
    fmtDate(a.at),
    a.actor_user_id ? (who[a.actor_user_id] || h("code", {}, a.actor_user_id.slice(0, 8))) : h("span", { class: "muted" }, "système"),
    ACTIONS[a.action] || a.action,
    h("code", { class: "small" }, JSON.stringify(a.detail)),
  ]), "Journal vide.");
}

// ------------------------------------------------------------------ rendu

const app = () => document.getElementById("app");
let renderSeq = 0;

async function render() {
  const seq = ++renderSeq;
  const parts = route();
  if (parts[0] === "oidc" && parts[1]) { await finishOidc(parts[1]); return; }
  if (parts[0] === "oidc-error") {
    history.replaceState(null, "", "#/login");
    storage.set(null);
    state.me = null;
    app().replaceChildren(loginView());
    flash(OIDC_ERRORS[parts[1]] || OIDC_ERRORS.token, "error");
    return;
  }
  if (!storage.get()) {
    if (parts[0] !== "login") { location.hash = "#/login"; return; }
    // Ne pas reconstruire le formulaire déjà affiché (on perdrait la saisie).
    if (!app().querySelector("main.login")) app().replaceChildren(loginView());
    return;
  }
  if (parts[0] === "login") { location.hash = "#/"; return; }
  try {
    if (!state.me) await loadMe();
    let content;
    if (parts[0] === "users") content = await usersView();
    else if (parts[0] === "account") content = await accountView();
    else if (parts[0] === "book") content = await bookView();
    else if (parts[0] === "e" && parts[1]) content = await entityView(parts[1], parts[2]);
    else content = await entitiesView();
    if (seq !== renderSeq) return;
    app().replaceChildren(...shell(content));
    if (pendingFlash) {
      const f = pendingFlash;
      pendingFlash = null;
      flash(f.message, f.kind);
      pendingFlash = null;
    }
  } catch (e) {
    if (e.status === 401) return;
    if (seq !== renderSeq) return;
    if (!state.me) { app().replaceChildren(h("main", {}, h("div", { class: "banner error" }, e.message))); return; }
    app().replaceChildren(...shell(h("div", { class: "banner error", role: "alert" }, e.message)));
  }
}

window.addEventListener("hashchange", () => { pendingFlash = null; render(); });
render();
