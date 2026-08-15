const COOKIE_NAME = 'snet_session';
const SESSION_TTL = 8 * 60 * 60;
const PBKDF2_ITERATIONS = 20000;
const encoder = new TextEncoder();

const ALL_MODULES = ['dashboard','clientes','visitas','orcamentos','servicos','producao','materiaisos','corte','agenda','garantias','estoque','compras','pdv','receber','pagar','caixa','relatorios','config'];
const PROFILE_PRESETS = {
  loja: ['dashboard','clientes','visitas','orcamentos','servicos','producao','materiaisos','corte','agenda','garantias','estoque','compras','pdv','receber','pagar','caixa','relatorios'],
  vendedor: ['dashboard','clientes','visitas','orcamentos','servicos','agenda','pdv'],
  serralheiro: ['dashboard','producao','materiaisos','corte','agenda','garantias'],
  custom: ['dashboard']
};
const MODULE_DATA_KEYS = {
  clientes:['clients'], visitas:['visits'], orcamentos:['budgets'], servicos:['catalog'], producao:['jobs'],
  materiaisos:['jobMaterials','stock','stockMovements'], agenda:['schedule'], garantias:['warranties'], estoque:['stock','stockMovements'],
  compras:['suppliers','purchases','payables'], pdv:['sales','cash','receivables'], receber:['receivables','cash'], pagar:['payables','cash'],
  caixa:['cash'], config:['config','employees']
};
const STATE_ARRAYS = ['clients','visits','catalog','budgets','jobs','jobMaterials','stockMovements','warranties','employees','schedule','stock','suppliers','purchases','sales','receivables','payables','cash'];
function uniqueModules(v){ return [...new Set((Array.isArray(v)?v:[]).filter(x=>ALL_MODULES.includes(x)))]; }
function parsePermissions(v){ try { return uniqueModules(typeof v === 'string' ? JSON.parse(v||'[]') : v); } catch { return []; } }
function normalizedProfile(v){ return ['loja','vendedor','serralheiro','custom'].includes(v) ? v : 'custom'; }
function hydrateUser(row){
  if(!row)return null;
  if(row.role==='admin') return {...row,profile:'admin',permissions:[...ALL_MODULES],employeeId:row.employee_id||'',ownJobsOnly:false};
  const profile=normalizedProfile(row.profile); let permissions=parsePermissions(row.permissions);
  if(!permissions.length) permissions=[...(PROFILE_PRESETS[profile]||['dashboard'])];
  if(!permissions.includes('dashboard')) permissions.unshift('dashboard');
  return {...row,profile,permissions,employeeId:row.employee_id||'',ownJobsOnly:!!row.own_jobs_only};
}
function writableKeys(user){
  if(user.role==='admin') return new Set(['config',...STATE_ARRAYS]);
  const out=new Set(); for(const m of user.permissions||[]) for(const k of MODULE_DATA_KEYS[m]||[]) out.add(k); return out;
}
function blankState(full={}){
  const out={config:{name:full.config?.name||'Serralheria Net',phone:full.config?.phone||'',address:full.config?.address||'',cnpj:'',margin:0,validity:10}};
  for(const k of STATE_ARRAYS)out[k]=[]; return out;
}
function filterState(full,user){
  if(!full)return null; if(user.role==='admin')return full;
  const out=blankState(full), keys=writableKeys(user);
  for(const k of keys){ if(k==='config') out.config=full.config||out.config; else out[k]=Array.isArray(full[k])?[...full[k]]:full[k]; }
  let jobs=Array.isArray(full.jobs)?full.jobs:[];
  if(user.ownJobsOnly && user.employeeId) jobs=jobs.filter(j=>j.assignedEmployeeId===user.employeeId || j.responsibleEmployeeId===user.employeeId);
  if((user.permissions||[]).includes('dashboard') || (user.permissions||[]).includes('producao')) out.jobs=jobs.map(j=>((user.permissions||[]).includes('orcamentos')||(user.permissions||[]).includes('relatorios'))?j:{...j,value:0,cost:0});
  const jobIds=new Set(out.jobs.map(j=>j.id));
  if((user.permissions||[]).includes('materiaisos')){
    out.jobMaterials=(full.jobMaterials||[]).filter(m=>!user.ownJobsOnly||jobIds.has(m.jobId)).map(m=>(user.permissions||[]).includes('estoque')?m:{...m,unitCost:0});
    if(!(user.permissions||[]).includes('estoque')) out.stock=(full.stock||[]).map(s=>({...s,cost:0}));
  }
  if((user.permissions||[]).includes('garantias') && user.ownJobsOnly) out.warranties=(full.warranties||[]).filter(w=>!w.jobId||jobIds.has(w.jobId));
  if(!(user.permissions||[]).includes('clientes')){
    const ids=new Set(out.jobs.map(j=>j.clientId).filter(Boolean));
    for(const a of out.schedule||[])if(a.clientId)ids.add(a.clientId);
    out.clients=(full.clients||[]).filter(c=>ids.has(c.id)).map(c=>({id:c.id,name:c.name,phone:c.phone,address:c.address,doc:'',notes:''}));
  }
  if((user.permissions||[]).includes('dashboard') && !(user.permissions||[]).includes('pdv')) out.sales=[];
  if(!(user.permissions||[]).includes('receber')) out.receivables=[];
  if(!(user.permissions||[]).includes('pagar')) out.payables=[];
  if(!(user.permissions||[]).includes('caixa')) out.cash=[];
  return out;
}

const nowSec = () => Math.floor(Date.now() / 1000);
const json = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra }
});

function bytesToB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64ToBytes(s) {
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function randomToken(size = 32) { const b = new Uint8Array(size); crypto.getRandomValues(b); return b64url(b); }
function randomSalt() { const b = new Uint8Array(16); crypto.getRandomValues(b); return bytesToB64(b); }
function hex(buffer) { return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function sha256(text) { return hex(await crypto.subtle.digest('SHA-256', encoder.encode(text))); }
async function passwordHash(password, saltB64) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64ToBytes(saltB64), iterations: PBKDF2_ITERATIONS }, key, 256);
  return hex(bits);
}
function safeEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let v = 0; for (let i = 0; i < a.length; i++) v |= a.charCodeAt(i) ^ b.charCodeAt(i); return v === 0;
}
function cookies(req) {
  const h = req.headers.get('cookie') || ''; const out = {};
  for (const part of h.split(';')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); }
  return out;
}
function sessionCookie(token) { return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`; }
function clearCookie() { return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`; }

async function ensureSchema(db) {
  await db.batch([
    db.prepare(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','employee')), active INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 1,
      updated_at INTEGER NOT NULL, updated_by TEXT
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
      attempt_key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL,
      blocked_until INTEGER NOT NULL DEFAULT 0
    )`),
    db.prepare(`CREATE TABLE IF NOT EXISTS user_access (
      user_id TEXT PRIMARY KEY, profile TEXT NOT NULL DEFAULT 'custom', permissions TEXT NOT NULL DEFAULT '[]',
      employee_id TEXT, own_jobs_only INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )`)
  ]);
}

async function readBody(req, max = 2_000_000) {
  const len = Number(req.headers.get('content-length') || 0);
  if (len > max) throw new Error('payload_too_large');
  const text = await req.text();
  if (text.length > max) throw new Error('payload_too_large');
  return text ? JSON.parse(text) : {};
}
function validUsername(v) { return /^[a-z0-9._-]{3,64}$/i.test(v || ''); }
function validPassword(v) { return typeof v === 'string' && v.length >= 8 && v.length <= 128; }

async function getSession(req, env) {
  const token = cookies(req)[COOKIE_NAME]; if (!token) return null;
  const tokenHash = await sha256(token); const n = nowSec();
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.active,s.expires_at,a.profile,a.permissions,a.employee_id,a.own_jobs_only
    FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN user_access a ON a.user_id=u.id
    WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(tokenHash, n).first();
  return hydrateUser(row);
}
async function requireAdmin(req, env) { const u = await getSession(req, env); return u?.role === 'admin' ? u : null; }

async function setup(req, env) {
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  if ((count?.n || 0) > 0) return json({ error: 'already_initialized' }, 409);
  const body = await readBody(req); const username = String(body.username || '').trim().toLowerCase(); const password = body.password;
  if (!validUsername(username)) return json({ error: 'invalid_username' }, 400);
  if (!validPassword(password)) return json({ error: 'weak_password' }, 400);

  let salt, hash, id, n;
  try {
    salt = randomSalt();
    hash = await passwordHash(password, salt);
    id = crypto.randomUUID();
    n = nowSec();
  } catch (err) {
    console.error('setup_crypto_error', err);
    return json({ error: 'setup_crypto_error' }, 500);
  }

  try {
    await env.DB.prepare("INSERT INTO users(id,username,password_hash,salt,role,active,created_at,updated_at) VALUES(?,?,?,?, 'admin',1,?,?)")
      .bind(id, username, hash, salt, n, n).run();
    await env.DB.prepare("INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,'admin',?,NULL,0,?)").bind(id,JSON.stringify(ALL_MODULES),n).run();
  } catch (err) {
    console.error('setup_db_error', err);
    return json({ error: 'setup_db_error' }, 500);
  }

  try {
    return await createSession(id, env);
  } catch (err) {
    console.error('setup_session_error', err);
    try { await env.DB.prepare('DELETE FROM users WHERE id=?').bind(id).run(); } catch {}
    return json({ error: 'setup_session_error' }, 500);
  }
}
async function createSession(userId, env) {
  const token = randomToken(); const tokenHash = await sha256(token); const n = nowSec();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(tokenHash, userId, n + SESSION_TTL, n).run();
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.active,a.profile,a.permissions,a.employee_id,a.own_jobs_only
    FROM users u LEFT JOIN user_access a ON a.user_id=u.id WHERE u.id=?`).bind(userId).first();
  const user=hydrateUser(row);
  return json({ ok: true, user:{id:user.id,username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly} }, 200, { 'set-cookie': sessionCookie(token) });
}
async function login(req, env) {
  const body = await readBody(req); const username = String(body.username || '').trim().toLowerCase(); const password = String(body.password || '');
  const ip = req.headers.get('cf-connecting-ip') || 'unknown'; const key = `${ip}:${username}`; const n = nowSec();
  const attempt = await env.DB.prepare('SELECT * FROM login_attempts WHERE attempt_key=?').bind(key).first();
  if (attempt?.blocked_until > n) return json({ error: 'temporarily_blocked' }, 429);
  const user = await env.DB.prepare('SELECT * FROM users WHERE username=? AND active=1').bind(username).first();
  let ok = false;
  if (user && validPassword(password)) ok = safeEqual(await passwordHash(password, user.salt), user.password_hash);
  if (!ok) {
    let attempts = 1, first = n; if (attempt && n - attempt.first_at < 900) { attempts = attempt.attempts + 1; first = attempt.first_at; }
    const blocked = attempts >= 5 ? n + 900 : 0;
    await env.DB.prepare(`INSERT INTO login_attempts(attempt_key,attempts,first_at,blocked_until) VALUES(?,?,?,?)
      ON CONFLICT(attempt_key) DO UPDATE SET attempts=excluded.attempts,first_at=excluded.first_at,blocked_until=excluded.blocked_until`)
      .bind(key, attempts, first, blocked).run();
    return json({ error: blocked ? 'temporarily_blocked' : 'invalid_credentials' }, blocked ? 429 : 401);
  }
  await env.DB.prepare('DELETE FROM login_attempts WHERE attempt_key=?').bind(key).run();
  return createSession(user.id, env);
}
async function logout(req, env) {
  const token = cookies(req)[COOKIE_NAME]; if (token) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256(token)).run();
  return json({ ok: true }, 200, { 'set-cookie': clearCookie() });
}

async function getData(env) {
  const row = await env.DB.prepare('SELECT data,version,updated_at FROM app_state WHERE id=1').first();
  if (!row) return { data: null, version: 0, updated_at: null };
  return { data: JSON.parse(row.data), version: row.version, updated_at: row.updated_at };
}
async function getDataForUser(env,user){ const s=await getData(env); return {...s,data:s.data?filterState(s.data,user):null}; }
async function putData(req, env, user) {
  const body = await readBody(req); if (!body || typeof body.data !== 'object' || body.data === null) return json({ error: 'invalid_data' }, 400);
  const row = await env.DB.prepare('SELECT data,version FROM app_state WHERE id=1').first(); const expected = Number(body.version || 0); const n = nowSec();
  if (row && expected !== Number(row.version)) return json({ error: 'version_conflict', version: row.version }, 409);
  const current=row?JSON.parse(row.data):blankState({}); const keys=writableKeys(user); let merged={...current};
  if(user.role==='admin') merged=body.data;
  else {
    for(const k of keys){
      if(!(k in body.data))continue;
      if(user.ownJobsOnly && user.employeeId && k==='jobs'){
        const incoming=Array.isArray(body.data.jobs)?body.data.jobs:[]; const byId=new Map((current.jobs||[]).map(j=>[j.id,j]));
        for(const j of incoming){ const old=byId.get(j.id); if(!old || (old.assignedEmployeeId!==user.employeeId && old.responsibleEmployeeId!==user.employeeId))continue;
          if(user.profile==='serralheiro') byId.set(j.id,{...old,status:j.status,progress:Number(j.progress||0),deadline:j.deadline||old.deadline,workNotes:j.workNotes??old.workNotes});
          else byId.set(j.id,{...old,...j}); }
        merged.jobs=[...byId.values()]; continue;
      }
      if(user.ownJobsOnly && user.employeeId && k==='jobMaterials'){
        const allowedJobs=new Set((current.jobs||[]).filter(j=>j.assignedEmployeeId===user.employeeId||j.responsibleEmployeeId===user.employeeId).map(j=>j.id));
        const incoming=(Array.isArray(body.data.jobMaterials)?body.data.jobMaterials:[]).filter(m=>allowedJobs.has(m.jobId));
        const keep=(current.jobMaterials||[]).filter(m=>!allowedJobs.has(m.jobId)); merged.jobMaterials=[...keep,...incoming]; continue;
      }
      merged[k]=body.data[k];
    }
  }
  const next = row ? Number(row.version) + 1 : 1; const text = JSON.stringify(merged);
  await env.DB.prepare(`INSERT INTO app_state(id,data,version,updated_at,updated_by) VALUES(1,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET data=excluded.data,version=excluded.version,updated_at=excluded.updated_at,updated_by=excluded.updated_by`)
    .bind(text, next, n, user.id).run();
  return json({ ok: true, version: next, updated_at: n });
}

async function listUsers(env) {
  const { results } = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.active,u.created_at,u.updated_at,a.profile,a.permissions,a.employee_id,a.own_jobs_only
    FROM users u LEFT JOIN user_access a ON a.user_id=u.id ORDER BY u.username`).all();
  return (results||[]).map(hydrateUser).map(u=>({id:u.id,username:u.username,role:u.role,active:u.active,created_at:u.created_at,updated_at:u.updated_at,profile:u.profile,permissions:u.permissions,employeeId:u.employeeId,ownJobsOnly:u.ownJobsOnly}));
}
async function createUser(req, env) {
  const b = await readBody(req); const username = String(b.username || '').trim().toLowerCase(); const password = b.password; const role = b.role === 'admin' ? 'admin' : 'employee';
  if (!validUsername(username) || !validPassword(password)) return json({ error: 'invalid_user' }, 400);
  const profile=role==='admin'?'admin':normalizedProfile(b.profile); const permissions=role==='admin'?[...ALL_MODULES]:uniqueModules(Array.isArray(b.permissions)?b.permissions:(PROFILE_PRESETS[profile]||['dashboard']));
  if(!permissions.includes('dashboard'))permissions.unshift('dashboard');
  const employeeId=role==='admin'?null:String(b.employeeId||'')||null, own=role==='admin'?0:(b.ownJobsOnly?1:0);
  const salt = randomSalt(), hash = await passwordHash(password, salt), id = crypto.randomUUID(), n = nowSec();
  try {
    await env.DB.prepare('INSERT INTO users(id,username,password_hash,salt,role,active,created_at,updated_at) VALUES(?,?,?,?,?,1,?,?)').bind(id,username,hash,salt,role,n,n).run();
    await env.DB.prepare('INSERT INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,?,?,?,?,?)').bind(id,profile,JSON.stringify(permissions),employeeId,own,n).run();
  } catch { return json({ error: 'username_exists' }, 409); }
  return json({ ok: true, id, user:{id,username,role,profile,permissions,employeeId,ownJobsOnly:!!own} }, 201);
}
async function patchUser(req, env, actor, id) {
  const target = await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first(); if (!target) return json({ error: 'not_found' }, 404);
  const oldAccess=await env.DB.prepare('SELECT * FROM user_access WHERE user_id=?').bind(id).first();
  const b = await readBody(req); const role = b.role === undefined ? target.role : (b.role === 'admin' ? 'admin' : 'employee'); const active = b.active === undefined ? target.active : (b.active ? 1 : 0);
  if ((target.role === 'admin') && (role !== 'admin' || !active)) { const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND active=1").first(); if ((c?.n || 0) <= 1) return json({ error: 'last_admin' }, 400); }
  if (actor.id === id && !active) return json({ error: 'cannot_disable_self' }, 400);
  const profile=role==='admin'?'admin':normalizedProfile(b.profile??oldAccess?.profile); let permissions=role==='admin'?[...ALL_MODULES]:uniqueModules(b.permissions!==undefined?b.permissions:parsePermissions(oldAccess?.permissions));
  if(!permissions.length)permissions=[...(PROFILE_PRESETS[profile]||['dashboard'])]; if(!permissions.includes('dashboard'))permissions.unshift('dashboard');
  const employeeId=role==='admin'?null:String(b.employeeId??oldAccess?.employee_id??'')||null; const own=role==='admin'?0:(b.ownJobsOnly===undefined?(oldAccess?.own_jobs_only||0):(b.ownJobsOnly?1:0));
  const n = nowSec();
  if (b.password !== undefined && b.password !== '') { if (!validPassword(b.password)) return json({ error: 'weak_password' }, 400); const salt = randomSalt(), hash = await passwordHash(b.password, salt); await env.DB.prepare('UPDATE users SET role=?,active=?,password_hash=?,salt=?,updated_at=? WHERE id=?').bind(role,active,hash,salt,n,id).run(); await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run(); }
  else await env.DB.prepare('UPDATE users SET role=?,active=?,updated_at=? WHERE id=?').bind(role,active,n,id).run();
  await env.DB.prepare(`INSERT INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET profile=excluded.profile,permissions=excluded.permissions,employee_id=excluded.employee_id,own_jobs_only=excluded.own_jobs_only,updated_at=excluded.updated_at`)
    .bind(id,profile,JSON.stringify(permissions),employeeId,own,n).run();
  return json({ ok: true });
}

function esc(s='') { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function loginPage(initialized) {
  const title = initialized ? 'Entrar no Serralheria Net' : 'Primeiro acesso';
  const button = initialized ? 'Entrar' : 'Criar administrador';
  return new Response(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>
  *{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#15242d;font-family:Segoe UI,Arial,sans-serif;color:#18212b}.box{width:min(420px,92vw);background:#fff;border-radius:18px;padding:30px;box-shadow:0 24px 70px #0006}.brand{font-size:28px;font-weight:800;color:#1f4e5f}.sub{color:#677381;margin:6px 0 24px}.field{margin:14px 0}.field label{display:block;font-size:13px;font-weight:700;margin-bottom:6px}.field input{width:100%;padding:12px;border:1px solid #dfe4e8;border-radius:10px;font-size:16px}.btn{width:100%;border:0;border-radius:10px;padding:13px;background:#d98b2b;color:#15242d;font-weight:800;font-size:16px}.err{min-height:22px;color:#b42318;font-size:13px;margin-top:12px}.note{font-size:12px;color:#677381;margin-top:16px}</style></head><body><main class="box"><div class="brand">Serralheria Net</div><div class="sub">${initialized?'Acesso protegido':'Configure o primeiro usuário administrador'}</div><form id="f"><div class="field"><label>Usuário</label><input id="u" autocomplete="username" required minlength="3"></div><div class="field"><label>Senha</label><input id="p" type="password" autocomplete="${initialized?'current-password':'new-password'}" required minlength="8"></div>${initialized?'':'<div class="note">A senha deve ter pelo menos 8 caracteres.</div>'}<button class="btn">${button}</button><div class="err" id="e"></div></form></main><script>
  f.onsubmit=async ev=>{ev.preventDefault();e.textContent='';const r=await fetch('${initialized?'/api/login':'/api/setup'}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});const j=await r.json().catch(()=>({}));if(r.ok){location.href='/';return}if(j.error==='already_initialized'){e.textContent='Administrador já criado. Atualizando…';setTimeout(()=>location.reload(),500);return}const msgs={temporarily_blocked:'Muitas tentativas. Tente novamente mais tarde.',weak_password:'Use uma senha com pelo menos 8 caracteres.',invalid_username:'Usuário inválido.',setup_crypto_error:'Erro ao proteger a senha. Tente novamente.',setup_db_error:'Erro ao gravar o administrador. Tente novamente.',setup_session_error:'Erro ao iniciar a sessão. O administrador não foi mantido; tente novamente.',server_error:'Erro interno no primeiro acesso. Tente novamente.'};e.textContent=msgs[j.error]||(initialized?'Usuário ou senha inválidos.':'Não foi possível criar o administrador.');};
  </script></body></html>`, { headers: { 'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-frame-options':'DENY','content-security-policy':"default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'" } });
}

function adminPage(user) {
  const page = `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Usuários · Serralheria Net</title><style>body{font-family:Segoe UI,Arial;background:#f4f6f8;margin:0;color:#18212b}main{max-width:900px;margin:auto;padding:24px}.card{background:white;border:1px solid #dfe4e8;border-radius:14px;padding:20px;margin:16px 0}input,select,button{padding:9px;border-radius:8px;border:1px solid #ccd3d8}button{cursor:pointer;background:#1f4e5f;color:white}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.user{display:grid;grid-template-columns:1fr auto auto auto;gap:8px;padding:10px 0;border-bottom:1px solid #eee}@media(max-width:650px){.user{grid-template-columns:1fr}}</style></head><body><main><div class="row"><h1 style="flex:1">Usuários do sistema</h1><a href="/">Voltar ao sistema</a></div><div class="card"><h2>Novo usuário</h2><form id="newf" class="row"><input id="nu" placeholder="usuário" required minlength="3"><input id="np" type="password" placeholder="senha (mín. 8)" required minlength="8"><select id="nr"><option value="employee">Funcionário</option><option value="admin">Administrador</option></select><button>Criar</button></form><div id="msg"></div></div><div class="card"><h2>Cadastrados</h2><div id="list">Carregando…</div></div></main><script>
function h(s){return String(s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
async function loadUsers(){const r=await fetch('/api/users');if(r.status===401){location='/';return}const users=await r.json();let html='';for(const x of users){html+='<div class="user"><strong>'+h(x.username)+'</strong><select data-role="'+x.id+'"><option value="employee" '+(x.role==='employee'?'selected':'')+'>Funcionário</option><option value="admin" '+(x.role==='admin'?'selected':'')+'>Administrador</option></select><label><input type="checkbox" data-active="'+x.id+'" '+(x.active?'checked':'')+'> Ativo</label><button data-save="'+x.id+'">Salvar</button></div>'}document.getElementById('list').innerHTML=html;document.querySelectorAll('[data-save]').forEach(function(b){b.onclick=function(){saveUser(b.getAttribute('data-save'))}})}
async function saveUser(id){const role=document.querySelector('[data-role="'+id+'"]').value,active=document.querySelector('[data-active="'+id+'"]').checked;const p=prompt('Nova senha (deixe em branco para manter):')||'';const body={role:role,active:active};if(p)body.password=p;const r=await fetch('/api/users/'+encodeURIComponent(id),{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify(body)});if(!r.ok)alert((await r.json()).error);loadUsers()}
document.getElementById('newf').onsubmit=async function(ev){ev.preventDefault();const r=await fetch('/api/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:document.getElementById('nu').value,password:document.getElementById('np').value,role:document.getElementById('nr').value})});document.getElementById('msg').textContent=r.ok?'Usuário criado.':'Não foi possível criar o usuário.';if(r.ok){ev.target.reset();loadUsers()}};loadUsers();
</script></body></html>`;
  return new Response(page, { headers: { 'content-type':'text/html; charset=utf-8','cache-control':'no-store' } });
}

function injectScript(state, user) {
  const stateText = state.data ? JSON.stringify(JSON.stringify(state.data)) : 'null';
  const userText = JSON.stringify({ username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly });
  return `<script>(()=>{const KEY='serralheria_net_v1';const remote=${stateText};window.__SNET_VERSION__=${Number(state.version||0)};window.__SNET_USER__=${userText};window.__SNET_HAS_REMOTE__=${state.data?'true':'false'};if(remote)localStorage.setItem(KEY,remote);const original=Storage.prototype.setItem;let t;Storage.prototype.setItem=function(k,v){original.apply(this,arguments);if(this===localStorage&&k===KEY){clearTimeout(t);t=setTimeout(async()=>{try{const r=await fetch('/api/data',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({data:JSON.parse(v),version:window.__SNET_VERSION__})});const j=await r.json();if(r.ok)window.__SNET_VERSION__=j.version;else if(r.status===409){alert('Os dados foram alterados em outro aparelho. Atualize a página antes de continuar.')}}catch(e){}},350)}};addEventListener('DOMContentLoaded',()=>{if(!window.__SNET_HAS_REMOTE__&&window.__SNET_USER__.role==='admin'){const v=localStorage.getItem(KEY);if(v)fetch('/api/data',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({data:JSON.parse(v),version:0})}).then(r=>r.json()).then(j=>{if(j.version)window.__SNET_VERSION__=j.version})}const bar=document.createElement('div');bar.style.cssText='position:fixed;right:12px;bottom:12px;z-index:99999;background:#15242d;color:white;padding:8px 10px;border-radius:10px;font:12px Segoe UI,Arial;box-shadow:0 4px 18px #0005';const labels={admin:'Administrador',loja:'Loja',vendedor:'Vendedor',serralheiro:'Serralheiro',custom:'Personalizado'};bar.innerHTML='<b>'+window.__SNET_USER__.username+'</b> · '+(labels[window.__SNET_USER__.profile]||'Funcionário')+' &nbsp; '+(window.__SNET_USER__.role==='admin'?'<a href="/admin-users" style="color:#ffd38d">Usuários</a> · ':'')+'<a href="#" id="snetLogout" style="color:#ffd38d">Sair</a>';document.body.appendChild(bar);document.getElementById('snetLogout').onclick=async e=>{e.preventDefault();await fetch('/api/logout',{method:'POST'});location.reload()}})})();</script>`;
}

export default {
  async fetch(req, env) {
    try {
      await ensureSchema(env.DB);
      const url = new URL(req.url); const p = url.pathname;
      if (p === '/sw.js') return new Response(`self.addEventListener('install',e=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.map(x=>caches.delete(x)))).then(()=>self.clients.claim())));`, { headers:{'content-type':'application/javascript','cache-control':'no-store'} });
      if (p === '/api/status' && req.method === 'GET') { const c=await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first(); return json({ initialized:(c?.n||0)>0 }); }
      if (p === '/api/setup' && req.method === 'POST') return setup(req, env);
      if (p === '/api/login' && req.method === 'POST') return login(req, env);
      if (p === '/api/logout' && req.method === 'POST') return logout(req, env);
      const user = await getSession(req, env);
      if (p.startsWith('/api/')) {
        if (!user) return json({ error:'unauthorized' },401);
        if (p === '/api/me' && req.method === 'GET') return json({ user:{id:user.id,username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly} });
        if (p === '/api/data' && req.method === 'GET') return json(await getDataForUser(env,user));
        if (p === '/api/data' && req.method === 'PUT') return putData(req, env, user);
        if (p === '/api/users' && req.method === 'GET') { if(user.role!=='admin')return json({error:'forbidden'},403); return json(await listUsers(env)); }
        if (p === '/api/users' && req.method === 'POST') { if(user.role!=='admin')return json({error:'forbidden'},403); return createUser(req, env); }
        if (p.startsWith('/api/users/') && req.method === 'PATCH') { if(user.role!=='admin')return json({error:'forbidden'},403); return patchUser(req,env,user,decodeURIComponent(p.slice('/api/users/'.length))); }
        return json({ error:'not_found' },404);
      }
      if (p === '/manifest.webmanifest' || p === '/icon.svg' || p === '/favicon.ico') return env.ASSETS.fetch(req);
      const initialized = ((await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first())?.n || 0) > 0;
      if (!user) return loginPage(initialized);
      if (p === '/admin-users') return user.role === 'admin' ? adminPage(user) : new Response('Acesso negado',{status:403});
      const asset = await env.ASSETS.fetch(req); const type = asset.headers.get('content-type') || '';
      if (type.includes('text/html')) { const state = await getDataForUser(env,user); return new HTMLRewriter().on('head',{element(e){e.append(injectScript(state,user),{html:true})}}).transform(asset); }
      return asset;
    } catch (e) {
      console.error(e); return json({ error: e?.message === 'payload_too_large' ? 'payload_too_large' : 'server_error' }, e?.message === 'payload_too_large' ? 413 : 500);
    }
  }
};
