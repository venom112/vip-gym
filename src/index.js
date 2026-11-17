// VIP GYM — نظام خصومات المرتبات | Cloudflare Worker + D1
// المصادقة والصلاحيات تُفرض هنا على الخادم (وليس في الواجهة فقط).

const COLS = ['employees', 'items', 'deductions', 'methods', 'statuses', 'policies', 'ktypes', 'settings'];
const PERMK = ['pd', 'pdE', 'pdD', 'pi', 'piE', 'piD', 'pe', 'peE', 'peD', 'ps', 'psX', 'nt', 'cpU', 'cpL', 'cpT', 'cpS', 'cpR'];
// [صلاحية الإضافة/التعديل, صلاحية الحذف]
const WRITE = {
  employees: ['peE', 'peD'],
  items: ['piE', 'piD'],
  deductions: ['pdE', 'pdD'],
  methods: ['cpL', 'cpL'],
  ktypes: ['cpL', 'cpL'],
  statuses: ['cpL', 'cpL'],
  policies: ['cpL', 'cpL'],
};
const SESSION_HOURS = 12;

class HttpErr extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const J = (o, status = 200, headers = {}) =>
  new Response(JSON.stringify(o), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });

/* ---------- تشفير ---------- */
const te = new TextEncoder();
const td = new TextDecoder();
const b64u = (buf) => {
  const a = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const unb64u = (s) => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
};
const hmacKey = (secret) =>
  crypto.subtle.importKey('raw', te.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
async function signToken(payload, secret) {
  const body = b64u(te.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret), te.encode(body));
  return body + '.' + b64u(sig);
}
async function verifyToken(token, secret) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  let ok = false;
  try { ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), unb64u(sig), te.encode(body)); } catch { return null; }
  if (!ok) return null;
  try { return JSON.parse(td.decode(unb64u(body))); } catch { return null; }
}
async function hashPw(pw, salt, iter = 100000) {
  const key = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: unb64u(salt), iterations: iter }, key, 256);
  return b64u(bits);
}
const newSalt = () => b64u(crypto.getRandomValues(new Uint8Array(16)));
const safeEq = (a, b) => {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};

/* ---------- مستخدمون وصلاحيات ---------- */
const pub = (r) => ({ id: r.id, name: r.name, role: r.role, active: !!r.active, perms: JSON.parse(r.perms || '{}') });
const uc = (u, k) => !!u && (u.role === 'admin' || u.role === 'owner' || !!(u.perms && u.perms[k]));
const need = (u, k) => { if (!uc(u, k)) throw new HttpErr(403, 'ليست لديك صلاحية لهذا الإجراء'); };
const allPerms = () => Object.fromEntries(PERMK.map((k) => [k, true]));
const isManager = (u) => !!u.active && (u.role === 'admin' || u.role === 'owner' || !!(u.perms && u.perms.cpU));

function cookie(token, url, maxAge = SESSION_HOURS * 3600) {
  return `sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}` + (url.protocol === 'https:' ? '; Secure' : '');
}
async function readBody(req) {
  const t = await req.text();
  if (t.length > 60000) throw new HttpErr(413, 'الحجم كبير');
  try { return t ? JSON.parse(t) : {}; } catch { throw new HttpErr(400, 'بيانات غير صالحة'); }
}
async function currentUser(req, env) {
  if (!env.SESSION_SECRET) throw new HttpErr(500, 'لم يتم ضبط SESSION_SECRET');
  const c = (req.headers.get('Cookie') || '').split(/;\s*/).find((x) => x.startsWith('sid='));
  if (!c) return null;
  const pl = await verifyToken(c.slice(4), env.SESSION_SECRET);
  if (!pl || !pl.u || pl.exp < Date.now()) return null;
  const r = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(pl.u).first();
  return r && r.active ? pub(r) : null;
}
async function requireUser(req, env) {
  const u = await currentUser(req, env);
  if (!u) throw new HttpErr(401, 'غير مسجّل الدخول');
  return u;
}
const bump = (env) => env.DB.prepare("INSERT INTO meta(k,v) VALUES('ver',1) ON CONFLICT(k) DO UPDATE SET v=v+1").run();
const stable = (o) => JSON.stringify(Object.keys(o).sort().map((k) => [k, o[k]]));

async function seedUser(env, id, name, role, pw) {
  const ex = await env.DB.prepare('SELECT 1 FROM users WHERE id=?').bind(id).first();
  if (ex) return;
  const salt = newSalt();
  await env.DB.prepare('INSERT OR IGNORE INTO users(id,name,role,active,perms,salt,hash,iter,updated) VALUES(?,?,?,?,?,?,?,?,?)')
    .bind(id, name, role, 1, JSON.stringify(allPerms()), salt, await hashPw(pw, salt), 100000, Date.now()).run();
}
// الحساب 'owner' يُنشأ تلقائياً ولا يظهر في قائمة المستخدمين ولا يمكن تعديله أو حذفه عبر الواجهة (أدناه).
// غيّر كلمة مروره فوراً بعد أول نشر، فهو ليس حماية — فقط حساب لا يمكن لأي أدمن آخر إزالته أو التحكم فيه من داخل النظام.
async function ensureAdmin(env) {
  await seedUser(env, 'admin', 'مدير النظام', 'admin', 'admin');
  await seedUser(env, 'owner', 'مالك النظام', 'owner', 'owner');
}

/* ---------- مسارات المصادقة ---------- */
async function login(req, env, url) {
  const b = await readBody(req);
  const u = String(b.username || '').trim().toLowerCase();
  const pw = String(b.password || '');
  if (!/^[a-z0-9_.-]{3,30}$/.test(u) || !pw) throw new HttpErr(401, 'بيانات الدخول غير صحيحة');
  await ensureAdmin(env);
  const ip = req.headers.get('CF-Connecting-IP') || 'local';
  const key = u + '|' + ip, now = Date.now();
  const at = await env.DB.prepare('SELECT n,t FROM login_attempts WHERE k=?').bind(key).first();
  if (at && at.n >= 8 && now - at.t < 15 * 60 * 1000) throw new HttpErr(429, 'محاولات كثيرة. حاول بعد ١٥ دقيقة.');
  const r = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(u).first();
  let good = false;
  if (r) good = safeEq(await hashPw(pw, r.salt, r.iter), r.hash);
  else await hashPw(pw, newSalt());
  if (!good) {
    await env.DB.prepare('INSERT INTO login_attempts(k,n,t) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=CASE WHEN ?-t>900000 THEN 1 ELSE n+1 END, t=?')
      .bind(key, now, now, now).run();
    throw new HttpErr(401, 'بيانات الدخول غير صحيحة');
  }
  if (!r.active) throw new HttpErr(403, 'هذا الحساب موقوف. تواصل مع المدير.');
  await env.DB.prepare('DELETE FROM login_attempts WHERE k=?').bind(key).run();
  const token = await signToken({ u, exp: now + SESSION_HOURS * 3600 * 1000 }, env.SESSION_SECRET);
  return J({ user: pub(r), weak: u === 'admin' && pw === 'admin' }, 200, { 'Set-Cookie': cookie(token, url) });
}

async function changePw(req, env) {
  const user = await requireUser(req, env);
  const b = await readBody(req);
  const oldPw = String(b.old || ''), nw = String(b.new || '');
  if (nw.length < 4 || nw.length > 200) throw new HttpErr(400, 'كلمة المرور الجديدة ٤ أحرف على الأقل');
  const r = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(user.id).first();
  if (!safeEq(await hashPw(oldPw, r.salt, r.iter), r.hash)) throw new HttpErr(401, 'كلمة المرور الحالية غير صحيحة');
  const salt = newSalt();
  await env.DB.prepare('UPDATE users SET salt=?,hash=?,iter=?,updated=? WHERE id=?')
    .bind(salt, await hashPw(nw, salt), 100000, Date.now(), user.id).run();
  return J({ ok: true });
}

/* ---------- إدارة المستخدمين ---------- */
async function allUsers(env) {
  const { results } = await env.DB.prepare('SELECT * FROM users ORDER BY id').all();
  return results.map(pub);
}
async function putUser(req, env, id) {
  const actor = await requireUser(req, env);
  need(actor, 'cpU');
  id = id.toLowerCase();
  if (id === 'owner') throw new HttpErr(403, 'هذا الحساب محمي ولا يمكن التحكم به');
  if (!/^[a-z0-9_.-]{3,30}$/.test(id)) throw new HttpErr(400, 'اسم المستخدم غير صالح');
  const b = await readBody(req);
  const name = String(b.name || '').trim().slice(0, 80);
  if (!name) throw new HttpErr(400, 'أدخل الاسم الكامل');
  const role = b.role === 'admin' ? 'admin' : 'user';
  const active = b.active !== false;
  const perms = role === 'admin' ? allPerms() : Object.fromEntries(PERMK.map((k) => [k, !!(b.perms && b.perms[k])]));
  const pw = b.password == null || b.password === '' ? null : String(b.password);
  const ex = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first();
  if (!ex && (!pw || pw.length < 4)) throw new HttpErr(400, 'كلمة المرور ٤ أحرف على الأقل');
  if (pw && (pw.length < 4 || pw.length > 200)) throw new HttpErr(400, 'كلمة المرور ٤ أحرف على الأقل');
  if (actor.role !== 'admin') {
    if (role === 'admin' || (ex && ex.role === 'admin')) throw new HttpErr(403, 'لا يمكنك إنشاء أو تعديل حسابات المديرين');
    if (PERMK.some((k) => perms[k] && !uc(actor, k))) throw new HttpErr(403, 'لا يمكنك منح صلاحية لا تملكها');
  }
  const next = { id, role, active, perms };
  if (id === actor.id && (!active || !isManager(next))) throw new HttpErr(400, 'لا يمكنك إزالة صلاحية إدارة المستخدمين أو إيقاف حسابك الحالي');
  const others = (await allUsers(env)).filter((u) => u.id !== id);
  if (!others.some(isManager) && !isManager(next)) throw new HttpErr(400, 'يجب أن يبقى مستخدم نشط واحد على الأقل يملك صلاحية إدارة المستخدمين');
  let salt = ex && ex.salt, hash = ex && ex.hash, iter = (ex && ex.iter) || 100000;
  if (pw) { salt = newSalt(); iter = 100000; hash = await hashPw(pw, salt, iter); }
  await env.DB.prepare(
    'INSERT INTO users(id,name,role,active,perms,salt,hash,iter,updated) VALUES(?,?,?,?,?,?,?,?,?) ' +
    'ON CONFLICT(id) DO UPDATE SET name=excluded.name,role=excluded.role,active=excluded.active,perms=excluded.perms,salt=excluded.salt,hash=excluded.hash,iter=excluded.iter,updated=excluded.updated'
  ).bind(id, name, role, active ? 1 : 0, JSON.stringify(perms), salt, hash, iter, Date.now()).run();
  await bump(env);
  return J({ ok: true });
}
async function deleteUser(req, env, id) {
  const actor = await requireUser(req, env);
  need(actor, 'cpU');
  id = id.toLowerCase();
  if (id === 'owner') throw new HttpErr(403, 'هذا الحساب محمي ولا يمكن حذفه');
  if (id === actor.id) throw new HttpErr(400, 'لا يمكنك حذف حسابك الحالي');
  const ex = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first();
  if (!ex) throw new HttpErr(404, 'غير موجود');
  if (actor.role !== 'admin' && ex.role === 'admin') throw new HttpErr(403, 'لا يمكنك حذف حساب مدير');
  if (!(await allUsers(env)).filter((u) => u.id !== id).some(isManager)) throw new HttpErr(400, 'يجب أن يبقى مستخدم نشط واحد على الأقل يملك صلاحية إدارة المستخدمين');
  await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run();
  await bump(env);
  return J({ ok: true });
}

/* ---------- البيانات ---------- */
async function listCol(env, col) {
  const { results } = await env.DB.prepare('SELECT data FROM docs WHERE col=?').bind(col).all();
  return results.map((r) => JSON.parse(r.data));
}
async function getDoc(env, col, id) {
  const r = await env.DB.prepare('SELECT data FROM docs WHERE col=? AND id=?').bind(col, id).first();
  return r ? JSON.parse(r.data) : null;
}
async function writeDoc(env, user, col, id, method, b) {
  if (!COLS.includes(col)) throw new HttpErr(404, 'غير موجود');
  const old = await getDoc(env, col, id);
  if (method === 'DELETE') {
    if (col === 'settings') throw new HttpErr(403, 'غير مسموح');
    need(user, WRITE[col][1]);
    await env.DB.prepare('DELETE FROM docs WHERE col=? AND id=?').bind(col, id).run();
    await bump(env);
    return;
  }
  if (!b || typeof b !== 'object' || Array.isArray(b)) throw new HttpErr(400, 'بيانات غير صالحة');
  const doc = method === 'PATCH' ? { ...(old || {}), ...b } : { ...b };
  if (col === 'settings') {
    if (id !== 'main') throw new HttpErr(404, 'غير موجود');
    const o = old || {};
    for (const k of new Set([...Object.keys(doc), ...Object.keys(o)])) {
      if (JSON.stringify(doc[k]) === JSON.stringify(o[k])) continue;
      const pk = k === 'name' ? 'cpS' : ['tpl', 'tplDay', 'tplLine'].includes(k) ? 'cpT' : null;
      if (!pk) throw new HttpErr(403, 'حقل غير مسموح');
      need(user, pk);
    }
  } else {
    if (doc.id === undefined) doc.id = /^\d+$/.test(id) ? Number(id) : id;
    const pk = WRITE[col][0];
    if (col === 'deductions' && old && !uc(user, pk) && uc(user, 'nt')) {
      const a = { ...old }, c = { ...doc };
      delete a.nt; delete c.nt;
      if (stable(a) !== stable(c)) throw new HttpErr(403, 'ليست لديك صلاحية لهذا الإجراء');
    } else need(user, pk);
  }
  const data = JSON.stringify(doc);
  if (data.length > 50000) throw new HttpErr(413, 'الحجم كبير');
  await env.DB.prepare('INSERT INTO docs(col,id,data,updated) VALUES(?,?,?,?) ON CONFLICT(col,id) DO UPDATE SET data=excluded.data,updated=excluded.updated')
    .bind(col, id, data, Date.now()).run();
  await bump(env);
}

/* ---------- الموجّه ---------- */
async function api(req, env, url) {
  const m = req.method;
  const p = url.pathname.slice(5).split('/').filter(Boolean).map(decodeURIComponent);
  if (m !== 'GET' && m !== 'HEAD') {
    const o = req.headers.get('Origin');
    if (o && new URL(o).host !== url.host) throw new HttpErr(403, 'مصدر غير مسموح');
  }
  const [a, b, c] = p;
  if (a === 'login' && m === 'POST') return login(req, env, url);
  if (a === 'logout' && m === 'POST') return J({ ok: true }, 200, { 'Set-Cookie': cookie('', url, 0) });
  if (a === 'ver' && m === 'GET') {
    const r = await env.DB.prepare("SELECT v FROM meta WHERE k='ver'").first();
    return J({ v: r ? r.v : 0 });
  }
  if (a === 'me' && m === 'GET') return J({ user: await currentUser(req, env) });
  if (a === 'changepw' && m === 'POST') return changePw(req, env);
  if (a === 'reset' && m === 'POST') {
    const u = await requireUser(req, env);
    need(u, 'cpR');
    await env.DB.prepare("DELETE FROM docs WHERE col IN ('employees','deductions')").run();
    await bump(env);
    return J({ ok: true });
  }
  if (a === 'users') {
    if (!b && m === 'GET') {
      const u = await requireUser(req, env);
      need(u, 'cpU');
      return J({ docs: (await allUsers(env)).filter((x) => x.role !== 'owner') });
    }
    if (b && m === 'PUT') return putUser(req, env, b);
    if (b && m === 'DELETE') return deleteUser(req, env, b);
  }
  if (a === 'c' && b && m === 'GET') {
    await requireUser(req, env);
    if (!COLS.includes(b)) throw new HttpErr(404, 'غير موجود');
    return J({ docs: await listCol(env, b) });
  }
  if (a === 'd' && b && c) {
    if (m === 'GET') {
      if (!COLS.includes(b)) throw new HttpErr(404, 'غير موجود');
      if (!(b === 'settings' && c === 'main')) await requireUser(req, env);
      return J({ data: await getDoc(env, b, c) });
    }
    if (m === 'PUT' || m === 'PATCH' || m === 'DELETE') {
      const u = await requireUser(req, env);
      await writeDoc(env, u, b, c, m, m === 'DELETE' ? null : await readBody(req));
      return J({ ok: true });
    }
  }
  throw new HttpErr(404, 'غير موجود');
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      return await api(req, env, url);
    } catch (e) {
      if (e instanceof HttpErr) return J({ error: e.message }, e.status);
      console.error(e);
      return J({ error: 'خطأ في الخادم' }, 500);
    }
  },
};
