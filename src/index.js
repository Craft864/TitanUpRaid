/* ================================================================
   Titan Up — Cloudflare Worker backend
   Battle.net login + guild-roster gating + shared page storage
   ----------------------------------------------------------------
   Config comes from wrangler.jsonc (vars) and dashboard secrets:
     SECRETS (dashboard → Settings → Variables and Secrets, encrypted):
       BNET_CLIENT_ID
       BNET_CLIENT_SECRET
     VARS (wrangler.jsonc):
       BNET_REGION        e.g. "us"
       GUILD_REALM_SLUG   e.g. "medivh"
       GUILD_NAME_SLUG    e.g. "titan-up"
       EDITOR_BATTLETAGS  comma list, e.g. "You#1234"
       ALLOWLIST_NAMES    comma list of character names or battletags
     BINDINGS:
       ASSETS  (static assets, the public/ folder)
       TU_KV   (KV namespace)
   ================================================================ */

const OAUTH = {
  authorize: "https://oauth.battle.net/authorize",
  token: "https://oauth.battle.net/token",
  userinfo: "https://oauth.battle.net/userinfo",
};
const SESSION_TTL = 60 * 60 * 24 * 7; // 7 days

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    try {
      if (path === "/auth/login") return handleLogin(request, env, url);
      if (path === "/auth/callback") return handleCallback(request, env, url);
      if (path === "/auth/logout") return handleLogout(request, env);
      if (path === "/api/me") return handleMe(request, env);
      if (path === "/api/data") return handleData(request, env);
      return handleApp(request, env);
    } catch (e) {
      return new Response("Server error: " + (e && e.message ? e.message : e), { status: 500 });
    }
  },
};

/* ---------- helpers ---------- */
function getCookie(request, name) {
  const h = request.headers.get("Cookie") || "";
  const m = h.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function json(obj, status) {
  return new Response(JSON.stringify(obj), { status: status || 200, headers: { "Content-Type": "application/json" } });
}
function htmlResponse(html, status) {
  return new Response(html, { status: status || 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
function editorSet(env) {
  return new Set((env.EDITOR_BATTLETAGS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean));
}
async function getSession(request, env) {
  const sid = getCookie(request, "tu_session");
  if (!sid) return null;
  const raw = await env.TU_KV.get("session:" + sid);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

/* ---------- OAuth ---------- */
function handleLogin(request, env, url) {
  const state = crypto.randomUUID();
  const redirectUri = url.origin + "/auth/callback";
  const authUrl = new URL(OAUTH.authorize);
  authUrl.searchParams.set("client_id", env.BNET_CLIENT_ID);
  authUrl.searchParams.set("scope", "openid wow.profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  const headers = new Headers();
  headers.append("Set-Cookie", "tu_state=" + state + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600");
  headers.set("Location", authUrl.toString());
  return new Response(null, { status: 302, headers });
}

async function handleCallback(request, env, url) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const savedState = getCookie(request, "tu_state");
  if (!code || !state || state !== savedState) {
    return htmlResponse(landingPage("Login couldn\u2019t be verified (state mismatch). Please try again."), 400);
  }
  const redirectUri = url.origin + "/auth/callback";
  const basic = "Basic " + btoa(env.BNET_CLIENT_ID + ":" + env.BNET_CLIENT_SECRET);

  // 1) exchange code for a user access token
  const tokenRes = await fetch(OAUTH.token, {
    method: "POST",
    headers: { "Authorization": basic, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri }),
  });
  if (!tokenRes.ok) return htmlResponse(landingPage("Battle.net login failed during token exchange."), 400);
  const token = await tokenRes.json();
  const userToken = token.access_token;

  // 2) who is this? (battletag + account id)
  let battletag = "Unknown", sub = "";
  const uiRes = await fetch(OAUTH.userinfo, { headers: { Authorization: "Bearer " + userToken } });
  if (uiRes.ok) { const ui = await uiRes.json(); battletag = ui.battletag || battletag; sub = ui.sub || ""; }

  // 3) their WoW characters
  const chars = [];
  const region = env.BNET_REGION || "us";
  const profRes = await fetch(
    "https://" + region + ".api.blizzard.com/profile/user/wow?namespace=profile-" + region + "&locale=en_US",
    { headers: { Authorization: "Bearer " + userToken } }
  );
  if (profRes.ok) {
    const prof = await profRes.json();
    (prof.wow_accounts || []).forEach(acc => (acc.characters || []).forEach(c => {
      chars.push({ name: (c.name || "").toLowerCase(), realm: (c.realm && c.realm.slug) || "" });
    }));
  }

  // 4) membership + editor status
  const isMemberByRoster = await checkMembership(env, chars, battletag);
  const isEditor = editorSet(env).has((battletag || "").toLowerCase());
  const isMember = isMemberByRoster || isEditor; // the editor can always view

  // 5) session
  const sid = crypto.randomUUID();
  const session = { battletag, sub, isMember, isEditor, ts: Date.now() };
  await env.TU_KV.put("session:" + sid, JSON.stringify(session), { expirationTtl: SESSION_TTL });

  const headers = new Headers();
  headers.append("Set-Cookie", "tu_session=" + sid + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + SESSION_TTL);
  headers.append("Set-Cookie", "tu_state=; Path=/; Max-Age=0");
  headers.set("Location", "/");
  return new Response(null, { status: 302, headers });
}

function handleLogout(request, env) {
  const sid = getCookie(request, "tu_session");
  if (sid) env.TU_KV.delete("session:" + sid);
  const headers = new Headers();
  headers.append("Set-Cookie", "tu_session=; Path=/; Max-Age=0");
  headers.set("Location", "/");
  return new Response(null, { status: 302, headers });
}

/* ---------- guild membership ---------- */
async function getAppToken(env) {
  const cached = await env.TU_KV.get("apptoken");
  if (cached) return cached;
  const basic = "Basic " + btoa(env.BNET_CLIENT_ID + ":" + env.BNET_CLIENT_SECRET);
  const res = await fetch(OAUTH.token, {
    method: "POST",
    headers: { "Authorization": basic, "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials" }),
  });
  if (!res.ok) throw new Error("app token request failed");
  const t = await res.json();
  await env.TU_KV.put("apptoken", t.access_token, { expirationTtl: Math.max(60, (t.expires_in || 86400) - 60) });
  return t.access_token;
}

async function checkMembership(env, chars, battletag) {
  const allow = (env.ALLOWLIST_NAMES || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  if (battletag && allow.includes(battletag.toLowerCase())) return true;
  for (const c of chars) if (allow.includes(c.name)) return true;
  if (chars.length === 0) return false;

  try {
    const region = env.BNET_REGION || "us";
    const appToken = await getAppToken(env);
    const rosterUrl = "https://" + region + ".api.blizzard.com/data/wow/guild/" +
      env.GUILD_REALM_SLUG + "/" + env.GUILD_NAME_SLUG + "/roster?namespace=profile-" + region + "&locale=en_US";
    const rRes = await fetch(rosterUrl, { headers: { Authorization: "Bearer " + appToken } });
    if (!rRes.ok) return false;
    const roster = await rRes.json();
    const pairSet = new Set(), nameSet = new Set();
    (roster.members || []).forEach(m => {
      const ch = m.character || {};
      const nm = (ch.name || "").toLowerCase();
      const slug = (ch.realm && ch.realm.slug) || "";
      if (nm) { nameSet.add(nm); if (slug) pairSet.add(nm + "|" + slug); }
    });
    for (const c of chars) {
      if (c.realm && pairSet.has(c.name + "|" + c.realm)) return true;
      if (nameSet.has(c.name)) return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

/* ---------- API ---------- */
async function handleMe(request, env) {
  const s = await getSession(request, env);
  return json({ loggedIn: !!s, isMember: !!(s && s.isMember), isEditor: !!(s && s.isEditor), name: s ? s.battletag : null });
}

async function handleData(request, env) {
  const s = await getSession(request, env);
  if (!s || !s.isMember) return json({ error: "forbidden" }, 403);
  if (request.method === "GET") {
    const raw = await env.TU_KV.get("guilddata");
    return json({ data: raw ? JSON.parse(raw) : null });
  }
  if (request.method === "POST") {
    if (!s.isEditor) return json({ error: "forbidden" }, 403);
    let body;
    try { body = await request.json(); } catch (e) { return json({ error: "bad json" }, 400); }
    if (!Array.isArray(body)) return json({ error: "expected an array" }, 400);
    await env.TU_KV.put("guilddata", JSON.stringify(body));
    return json({ ok: true });
  }
  return json({ error: "method not allowed" }, 405);
}

/* ---------- app / gating ---------- */
async function handleApp(request, env) {
  const s = await getSession(request, env);
  if (!s) return htmlResponse(landingPage(null), 200);
  if (!s.isMember) return htmlResponse(deniedPage(s.battletag), 200);
  return env.ASSETS.fetch(request); // serves public/index.html
}

/* ---------- static pages ---------- */
function shell(inner) {
  return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">' +
    '<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">' +
    '<title>Titan Up — Raid Guide</title><style>' +
    'body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:Inter,system-ui,sans-serif;color:#eef0f7;' +
    'background:radial-gradient(900px 500px at 20% -10%,rgba(145,71,255,.18),transparent 60%),radial-gradient(900px 500px at 100% 0,rgba(224,128,48,.14),transparent 58%),#0c0b12;text-align:center;padding:24px;}' +
    '.card{max-width:460px;}h1{font-family:"Space Grotesk",sans-serif;font-size:30px;letter-spacing:-1px;margin:0 0 6px;' +
    'background:linear-gradient(115deg,#ff9d43,#e08030 40%,#9147ff);-webkit-background-clip:text;background-clip:text;color:transparent;}' +
    '.sub{color:#8b90a6;font-size:13px;letter-spacing:2px;text-transform:uppercase;margin-bottom:26px;}' +
    'p{color:#b7bbca;line-height:1.6;}a.btn{display:inline-block;margin-top:20px;padding:13px 22px;border-radius:10px;font-weight:600;color:#fff;text-decoration:none;' +
    'background:linear-gradient(115deg,#ff9d43,#e08030 40%,#9147ff);box-shadow:0 6px 22px rgba(145,71,255,.35);}' +
    'a.muted{color:#ff9d43;text-decoration:none;font-size:13px;}</style></head><body><div class="card">' + inner + '</div></body></html>';
}
function landingPage(msg) {
  return shell(
    '<h1>TITAN UP</h1><div class="sub">Raid Guide</div>' +
    (msg ? '<p style="color:#ff8a8a">' + msg + '</p>' : '') +
    '<p>This guide is for Titan Up members. Sign in with your Battle.net account to continue.</p>' +
    '<a class="btn" href="/auth/login">Log in with Battle.net</a>'
  );
}
function deniedPage(name) {
  return shell(
    '<h1>TITAN UP</h1><div class="sub">Raid Guide</div>' +
    '<p>Signed in as <strong>' + (name || "") + '</strong>, but none of your characters are on the Titan Up (Medivh-US) roster yet.</p>' +
    '<p>If you just joined, the roster can take a little while to update — check back later, or ask an officer to add you to the allow-list.</p>' +
    '<a class="muted" href="/auth/logout">Log out / switch account</a>'
  );
}
