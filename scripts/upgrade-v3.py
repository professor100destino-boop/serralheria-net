from pathlib import Path


def replace_between(text, start_marker, end_marker, replacement):
    a = text.index(start_marker)
    b = text.index(end_marker, a)
    return text[:a] + replacement + text[b:]

worker_path = Path('src/worker.js')
index_path = Path('index.html')
schema_path = Path('schema.sql')
worker = worker_path.read_text()
index = index_path.read_text()
schema = schema_path.read_text()

# ---------------- BACKEND ----------------
anchor = "const encoder = new TextEncoder();\n"
if 'const ALL_MODULES' not in worker:
    worker = worker.replace(anchor, anchor + """
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
""")

# Add access table to ensureSchema.
old = """    db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (\n      attempt_key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL,\n      blocked_until INTEGER NOT NULL DEFAULT 0\n    )`)\n  ]);"""
new = """    db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (\n      attempt_key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 0, first_at INTEGER NOT NULL,\n      blocked_until INTEGER NOT NULL DEFAULT 0\n    )`),\n    db.prepare(`CREATE TABLE IF NOT EXISTS user_access (\n      user_id TEXT PRIMARY KEY, profile TEXT NOT NULL DEFAULT 'custom', permissions TEXT NOT NULL DEFAULT '[]',\n      employee_id TEXT, own_jobs_only INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL,\n      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE\n    )`)\n  ]);"""
if old in worker: worker = worker.replace(old,new)

worker = replace_between(worker, 'async function getSession(req, env) {', 'async function requireAdmin', """async function getSession(req, env) {
  const token = cookies(req)[COOKIE_NAME]; if (!token) return null;
  const tokenHash = await sha256(token); const n = nowSec();
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.active,s.expires_at,a.profile,a.permissions,a.employee_id,a.own_jobs_only
    FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN user_access a ON a.user_id=u.id
    WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(tokenHash, n).first();
  return hydrateUser(row);
}
""")

# First administrator gets full access record.
needle = """    await env.DB.prepare(\"INSERT INTO users(id,username,password_hash,salt,role,active,created_at,updated_at) VALUES(?,?,?,?, 'admin',1,?,?)\")\n      .bind(id, username, hash, salt, n, n).run();"""
repl = needle + '\n    await env.DB.prepare("INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,\'admin\',?,NULL,0,?)").bind(id,JSON.stringify(ALL_MODULES),n).run();'
if needle in worker and 'INSERT OR REPLACE INTO user_access' not in worker[worker.index(needle):worker.index(needle)+700]: worker=worker.replace(needle,repl)

worker = replace_between(worker, 'async function createSession(userId, env) {', 'async function login(req, env) {', """async function createSession(userId, env) {
  const token = randomToken(); const tokenHash = await sha256(token); const n = nowSec();
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(tokenHash, userId, n + SESSION_TTL, n).run();
  const row = await env.DB.prepare(`SELECT u.id,u.username,u.role,u.active,a.profile,a.permissions,a.employee_id,a.own_jobs_only
    FROM users u LEFT JOIN user_access a ON a.user_id=u.id WHERE u.id=?`).bind(userId).first();
  const user=hydrateUser(row);
  return json({ ok: true, user:{id:user.id,username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly} }, 200, { 'set-cookie': sessionCookie(token) });
}
""")

worker = replace_between(worker, 'async function getData(env) {', 'async function listUsers(env) {', """async function getData(env) {
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

""")

worker = replace_between(worker, 'async function listUsers(env) {', 'function esc(', """async function listUsers(env) {
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

""")

# Replace injectScript with access-aware injector.
worker = replace_between(worker, 'function injectScript(state, user) {', 'export default {', """function injectScript(state, user) {
  const stateText = state.data ? JSON.stringify(JSON.stringify(state.data)) : 'null';
  const userText = JSON.stringify({ username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly });
  return `<script>(()=>{const KEY='serralheria_net_v1';const remote=${stateText};window.__SNET_VERSION__=${Number(state.version||0)};window.__SNET_USER__=${userText};window.__SNET_HAS_REMOTE__=${state.data?'true':'false'};if(remote)localStorage.setItem(KEY,remote);const original=Storage.prototype.setItem;let t;Storage.prototype.setItem=function(k,v){original.apply(this,arguments);if(this===localStorage&&k===KEY){clearTimeout(t);t=setTimeout(async()=>{try{const r=await fetch('/api/data',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({data:JSON.parse(v),version:window.__SNET_VERSION__})});const j=await r.json();if(r.ok)window.__SNET_VERSION__=j.version;else if(r.status===409){alert('Os dados foram alterados em outro aparelho. Atualize a página antes de continuar.')}}catch(e){}},350)}};addEventListener('DOMContentLoaded',()=>{if(!window.__SNET_HAS_REMOTE__&&window.__SNET_USER__.role==='admin'){const v=localStorage.getItem(KEY);if(v)fetch('/api/data',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({data:JSON.parse(v),version:0})}).then(r=>r.json()).then(j=>{if(j.version)window.__SNET_VERSION__=j.version})}const bar=document.createElement('div');bar.style.cssText='position:fixed;right:12px;bottom:12px;z-index:99999;background:#15242d;color:white;padding:8px 10px;border-radius:10px;font:12px Segoe UI,Arial;box-shadow:0 4px 18px #0005';const labels={admin:'Administrador',loja:'Loja',vendedor:'Vendedor',serralheiro:'Serralheiro',custom:'Personalizado'};bar.innerHTML='<b>'+window.__SNET_USER__.username+'</b> · '+(labels[window.__SNET_USER__.profile]||'Funcionário')+' &nbsp; '+(window.__SNET_USER__.role==='admin'?'<a href="/admin-users" style="color:#ffd38d">Usuários</a> · ':'')+'<a href="#" id="snetLogout" style="color:#ffd38d">Sair</a>';document.body.appendChild(bar);document.getElementById('snetLogout').onclick=async e=>{e.preventDefault();await fetch('/api/logout',{method:'POST'});location.reload()}})})();</script>`;
}

""")

# Route API data through filtered state and expose access metadata.
worker = worker.replace("if (p === '/api/me' && req.method === 'GET') return json({ user:{id:user.id,username:user.username,role:user.role} });", "if (p === '/api/me' && req.method === 'GET') return json({ user:{id:user.id,username:user.username,role:user.role,profile:user.profile,permissions:user.permissions,employeeId:user.employeeId,ownJobsOnly:user.ownJobsOnly} });")
worker = worker.replace("if (p === '/api/data' && req.method === 'GET') return json(await getData(env));", "if (p === '/api/data' && req.method === 'GET') return json(await getDataForUser(env,user));")
worker = worker.replace("if (type.includes('text/html')) { const state = await getData(env);", "if (type.includes('text/html')) { const state = await getDataForUser(env,user);")

# ---------------- FRONTEND ----------------
# More accurate backup text.
index=index.replace('Esta versão salva os dados no próprio navegador. Faça backup regularmente.','Os dados principais são sincronizados no banco online. O backup continua disponível como cópia de segurança.')

# Access helpers after titles.
titles_line = "const titles={dashboard:'Dashboard',clientes:'Clientes',visitas:'Visitas e Medidas',orcamentos:'Orçamentos',servicos:'Produtos e Serviços',producao:'Produção / Ordens de Serviço',materiaisos:'Materiais por OS',corte:'Otimizador de Corte',agenda:'Agenda / Instalações',garantias:'Garantias',estoque:'Estoque',compras:'Compras / Fornecedores',pdv:'Caixa / Vendas',receber:'Contas a Receber',pagar:'Contas a Pagar',caixa:'Fluxo de Caixa',relatorios:'Relatórios',config:'Configurações'};"
access_js = titles_line + """
const accessProfiles={
 loja:['dashboard','clientes','visitas','orcamentos','servicos','producao','materiaisos','corte','agenda','garantias','estoque','compras','pdv','receber','pagar','caixa','relatorios'],
 vendedor:['dashboard','clientes','visitas','orcamentos','servicos','agenda','pdv'],
 serralheiro:['dashboard','producao','materiaisos','corte','agenda','garantias'], custom:['dashboard']
};
const profileLabels={admin:'Administrador',loja:'Loja',vendedor:'Vendedor',serralheiro:'Serralheiro',custom:'Personalizado'};
function currentAccess(){return window.__SNET_USER__||{role:'admin',profile:'admin',permissions:Object.keys(titles),employeeId:'',ownJobsOnly:false}}
function canAccess(id){let u=currentAccess();return u.role==='admin'||(u.permissions||[]).includes(id)}
function employeeName(id){return db.employees.find(x=>x.id===id)?.name||''}
function applyAccessUI(){
 const u=currentAccess();document.querySelectorAll('.nav-btn[data-page]').forEach(b=>b.style.display=canAccess(b.dataset.page)?'flex':'none');
 document.querySelectorAll('.nav-title').forEach(t=>{let n=t.nextElementSibling,show=false;while(n&&!n.classList.contains('nav-title')){if(n.classList?.contains('nav-btn')&&n.style.display!=='none')show=true;n=n.nextElementSibling}t.style.display=show?'block':'none'});
 const qa=document.querySelector('.top-actions');if(qa){qa.querySelectorAll('button').forEach((b,i)=>b.style.display=(i===0?canAccess('orcamentos'):canAccess('pdv'))?'inline-block':'none')}
 const alert=document.querySelector('#dashboard .alert');if(alert&&u.role!=='admin')alert.innerHTML='<strong>'+profileLabels[u.profile]+'</strong> — '+(u.profile==='serralheiro'?'acompanhe somente os serviços atribuídos a você e atualize o andamento da produção.':u.profile==='vendedor'?'acompanhe clientes, visitas, propostas e vendas permitidas ao seu perfil.':'acesso configurado conforme suas permissões.');
 if(u.profile==='serralheiro'||u.profile==='vendedor'){let f=document.getElementById('dashFinance')?.closest('.card');if(f)f.style.display='none';let s=document.getElementById('dashStock')?.closest('.card');if(s)s.style.display='none'}
 if(u.profile==='serralheiro'){let h=document.querySelector('#dashboard .section-title h2');if(h)h.textContent='Meus serviços em andamento'}
 let active=document.querySelector('.page.active');if(active&&!canAccess(active.id)){let first=[...document.querySelectorAll('.nav-btn[data-page]')].find(b=>b.style.display!=='none');if(first)go(first.dataset.page)}
}
"""
if 'const accessProfiles=' not in index: index=index.replace(titles_line,access_js)

old_go = """function go(id){\n document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));\n document.getElementById(id).classList.add('active');"""
new_go = """function go(id){\n if(!canAccess(id)){let first=[...document.querySelectorAll('.nav-btn[data-page]')].find(b=>canAccess(b.dataset.page));if(first&&first.dataset.page!==id)return go(first.dataset.page);return}\n document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));\n document.getElementById(id).classList.add('active');"""
index=index.replace(old_go,new_go)
index=index.replace("function quickNewBudget(){go('orcamentos');openBudget()}","function quickNewBudget(){if(!canAccess('orcamentos'))return alert('Seu perfil não possui acesso a Orçamentos.');go('orcamentos');openBudget()}")
index=index.replace("function quickNewSale(){go('pdv')}","function quickNewSale(){if(!canAccess('pdv'))return alert('Seu perfil não possui acesso ao Caixa/Vendas.');go('pdv')}")

# New jobs carry employee assignment.
index=index.replace("status:'Aguardando material',deadline:'',responsible:'',progress:10})", "status:'Aguardando material',deadline:'',responsible:'',assignedEmployeeId:'',progress:10,workNotes:''})")
index=index.replace("status:'Aguardando material',deadline:'',responsible:'',progress:10};", "status:'Aguardando material',deadline:'',responsible:'',assignedEmployeeId:'',progress:10,workNotes:''};")

# Replace Job editor/save with role-aware version.
job_start=index.index("function openJob(id=''){")
job_end=index.index('function renderJobs(){',job_start)
new_job = r'''function openJob(id=''){
 let x=db.jobs.find(a=>a.id===id)||{id:'',number:'OS-'+String(db.jobs.length+1).padStart(4,'0'),budgetId:'',clientId:'',title:'',value:0,cost:0,status:'Aguardando material',deadline:'',responsible:'',assignedEmployeeId:'',progress:10,workNotes:''};
 let u=currentAccess();
 if(u.profile==='serralheiro'){
  openModal('Atualizar meu serviço',`<form onsubmit="saveJob(event,'${x.id}')"><div class="form-grid"><div class="field w4"><label>OS</label><input value="${esc(x.number)}" disabled></div><div class="field w8"><label>Cliente / Serviço</label><input value="${esc(clientName(x.clientId)+' - '+x.title)}" disabled></div><div class="field w4"><label>Prazo</label><input type="date" name="deadline" value="${x.deadline}"></div><div class="field w4"><label>Progresso %</label><input type="number" min="0" max="100" name="progress" value="${x.progress||0}"></div><div class="field w4"><label>Etapa</label><select name="status">${['Aguardando material','Corte / Preparação','Soldagem / Montagem','Pintura / Acabamento','Pronto para instalar','Concluído'].map(s=>`<option ${s===x.status?'selected':''}>${s}</option>`)}</select></div><div class="field w12"><label>Observações do serviço</label><textarea name="workNotes" placeholder="Informe andamento, dificuldade, material faltante ou observação para a loja">${esc(x.workNotes||'')}</textarea></div><div class="field w12 right"><button class="btn primary">Atualizar serviço</button></div></div></form>`);return;
 }
 let team=db.employees.filter(e=>e.active!==false);let empOpts='<option value="">Sem responsável</option>'+team.map(e=>`<option value="${e.id}" ${e.id===x.assignedEmployeeId?'selected':''}>${esc(e.name+' - '+e.role)}</option>`).join('');
 openModal(id?'Editar OS':'Nova Ordem de Serviço',`<form onsubmit="saveJob(event,'${x.id}')"><div class="form-grid"><div class="field w3"><label>Número</label><input name="number" value="${esc(x.number)}" required></div><div class="field w6"><label>Cliente</label><select name="clientId" required>${opts(db.clients,x.clientId)}</select></div><div class="field w3"><label>Prazo</label><input type="date" name="deadline" value="${x.deadline}"></div><div class="field w12"><label>Serviço</label><input name="title" value="${esc(x.title)}" required></div><div class="field w3"><label>Valor vendido</label><input type="number" step=".01" name="value" value="${x.value}"></div><div class="field w3"><label>Custo estimado</label><input type="number" step=".01" name="cost" value="${x.cost}"></div><div class="field w3"><label>Responsável</label><select name="assignedEmployeeId">${empOpts}</select></div><div class="field w3"><label>Progresso %</label><input type="number" min="0" max="100" name="progress" value="${x.progress}"></div><div class="field w6"><label>Etapa</label><select name="status">${['Aguardando material','Corte / Preparação','Soldagem / Montagem','Pintura / Acabamento','Pronto para instalar','Concluído'].map(s=>`<option ${s===x.status?'selected':''}>${s}</option>`)}</select></div><div class="field w12"><label>Observações internas da OS</label><textarea name="workNotes">${esc(x.workNotes||'')}</textarea></div><div class="field w12 right"><button class="btn primary">Salvar OS</button></div></div></form>`)
}
function saveJob(e,id){e.preventDefault();let f=Object.fromEntries(new FormData(e.target)),x=id?db.jobs.find(x=>x.id===id):null;if('value'in f)f.value=+f.value;if('cost'in f)f.cost=+f.cost;if('progress'in f)f.progress=+f.progress;if('assignedEmployeeId'in f)f.responsible=employeeName(f.assignedEmployeeId);if(x)Object.assign(x,f);else db.jobs.push({id:uid('os'),budgetId:'',...f});closeModal();save()}
'''
index=index[:job_start]+new_job+index[job_end:]

# Employee access editor.
emp_start=index.index("// EQUIPE\nfunction openEmployee")
emp_end=index.index('// ESTOQUE',emp_start)
new_emp = r'''// EQUIPE / ACESSOS
function employeePermissionChecks(selected=[]){return Object.entries(titles).map(([k,v])=>`<label style="display:flex;gap:7px;align-items:center;border:1px solid var(--border);padding:8px;border-radius:8px"><input style="width:auto" type="checkbox" name="perm" value="${k}" ${selected.includes(k)?'checked':''} onchange="document.getElementById('empProfile').value='custom'"> ${esc(v)}</label>`).join('')}
function applyEmployeePreset(){let p=document.getElementById('empProfile')?.value;if(!p||p==='custom')return;let set=new Set(accessProfiles[p]||[]);document.querySelectorAll('input[name="perm"]').forEach(c=>c.checked=set.has(c.value));let own=document.getElementById('empOwnJobs');if(own&&p==='serralheiro')own.value='true'}
function openEmployee(id=''){
 let x=db.employees.find(a=>a.id===id)||{id:'',name:'',role:'Serralheiro',phone:'',commission:0,active:true,userId:'',username:'',profile:'serralheiro',permissions:accessProfiles.serralheiro,ownJobsOnly:true,accessEnabled:false};
 let selected=Array.isArray(x.permissions)?x.permissions:(accessProfiles[x.profile]||['dashboard']);
 openModal(id?'Editar funcionário e acesso':'Novo funcionário e acesso',`<form onsubmit="saveEmployee(event,'${x.id}')"><div class="form-grid"><div class="field w6"><label>Nome</label><input name="name" required value="${esc(x.name)}"></div><div class="field w6"><label>Função</label><select name="role"><option ${x.role==='Serralheiro'?'selected':''}>Serralheiro</option><option ${x.role==='Vendedor'?'selected':''}>Vendedor</option><option ${x.role==='Atendente'?'selected':''}>Atendente</option><option ${x.role==='Gerente'?'selected':''}>Gerente</option><option ${!['Serralheiro','Vendedor','Atendente','Gerente'].includes(x.role)?'selected':''}>Outro</option></select></div><div class="field w4"><label>Telefone</label><input name="phone" value="${esc(x.phone)}"></div><div class="field w4"><label>Comissão padrão (%)</label><input type="number" step=".01" name="commission" value="${x.commission||0}"></div><div class="field w4"><label>Status</label><select name="active"><option value="true" ${x.active!==false?'selected':''}>Ativo</option><option value="false" ${x.active===false?'selected':''}>Inativo</option></select></div><div class="field w12"><div class="hr"></div><h3 style="margin:0 0 8px">Acesso ao Serralheria Net</h3></div><div class="field w4"><label>Permitir login?</label><select name="accessEnabled"><option value="true" ${(x.accessEnabled||x.userId)?'selected':''}>Sim</option><option value="false" ${!(x.accessEnabled||x.userId)?'selected':''}>Não</option></select></div><div class="field w4"><label>Usuário</label><input name="username" value="${esc(x.username||'')}" ${x.userId?'readonly':''} placeholder="ex.: joao"></div><div class="field w4"><label>${x.userId?'Nova senha (opcional)':'Senha (mín. 8)'}</label><input type="password" name="password" minlength="8" autocomplete="new-password"></div><div class="field w4"><label>Perfil de acesso</label><select name="profile" id="empProfile" onchange="applyEmployeePreset()"><option value="loja" ${x.profile==='loja'?'selected':''}>Loja</option><option value="vendedor" ${x.profile==='vendedor'?'selected':''}>Vendedor</option><option value="serralheiro" ${x.profile==='serralheiro'?'selected':''}>Serralheiro</option><option value="custom" ${x.profile==='custom'?'selected':''}>Personalizado</option></select></div><div class="field w4"><label>OS visíveis</label><select name="ownJobsOnly" id="empOwnJobs"><option value="false" ${!x.ownJobsOnly?'selected':''}>Todas permitidas</option><option value="true" ${x.ownJobsOnly?'selected':''}>Somente atribuídas a ele</option></select></div><div class="field w12"><label>Módulos liberados</label><div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:7px">${employeePermissionChecks(selected)}</div></div><div class="field w12 right"><button class="btn primary">Salvar funcionário e acesso</button></div></div></form>`)
}
async function saveEmployee(e,id){
 e.preventDefault();let form=e.target,fd=new FormData(form),empId=id||uid('emp'),old=id?db.employees.find(x=>x.id===id):null;let permissions=[...form.querySelectorAll('input[name="perm"]:checked')].map(x=>x.value);let f={id:empId,name:fd.get('name'),role:fd.get('role'),phone:fd.get('phone'),commission:+fd.get('commission')||0,active:fd.get('active')==='true',accessEnabled:fd.get('accessEnabled')==='true',username:String(fd.get('username')||'').trim().toLowerCase(),profile:fd.get('profile'),permissions,ownJobsOnly:fd.get('ownJobsOnly')==='true',userId:old?.userId||''};
 if(f.accessEnabled){if(!f.username)return alert('Informe o usuário de acesso.');let payload={role:'employee',active:f.active,profile:f.profile,permissions:f.permissions,employeeId:empId,ownJobsOnly:f.ownJobsOnly};let pass=String(fd.get('password')||'');if(pass)payload.password=pass;if(f.userId){let r=await fetch('/api/users/'+encodeURIComponent(f.userId),{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});if(!r.ok)return alert('Não foi possível atualizar o acesso: '+((await r.json()).error||'erro'));}else{if(pass.length<8)return alert('Para o primeiro acesso informe uma senha com pelo menos 8 caracteres.');payload.username=f.username;let r=await fetch('/api/users',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}),j=await r.json();if(!r.ok)return alert('Não foi possível criar o usuário: '+(j.error||'erro'));f.userId=j.id;}}
 else if(f.userId){await fetch('/api/users/'+encodeURIComponent(f.userId),{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({active:false,employeeId:empId,profile:f.profile,permissions:f.permissions,ownJobsOnly:f.ownJobsOnly})})}
 if(old)Object.assign(old,f);else db.employees.push(f);closeModal();save()
}
function renderEmployees(){let el=document.getElementById('employeeList');if(!el)return;el.innerHTML=db.employees.map(x=>`<div class="list-item"><strong>${esc(x.name)}</strong> <span class="badge ${x.active!==false?'ok':'danger'}">${x.active!==false?'Ativo':'Inativo'}</span><div class="muted">${esc(x.role)} · ${esc(x.phone)} · Comissão ${x.commission||0}%</div><div style="margin-top:5px">${x.userId?`<span class="badge info">Login: ${esc(x.username)}</span> <span class="badge">${esc(profileLabels[x.profile]||'Personalizado')}</span> ${x.ownJobsOnly?'<span class="badge warn">Somente próprias OS</span>':''}`:'<span class="badge">Sem acesso ao sistema</span>'}</div><button class="btn small" style="margin-top:7px" onclick="openEmployee('${x.id}')">Editar dados e acesso</button></div>`).join('')||'<div class="muted">Nenhum funcionário cadastrado.</div>'}

'''
index=index[:emp_start]+new_emp+index[emp_end:]

# Safer print for workers: hide money if profile cannot see commercial/reporting data.
index=index.replace("<div class=\"hr\"></div><p><strong>Valor vendido:</strong> ${money(j.value)} &nbsp; <strong>Custo estimado:</strong> ${money(j.cost)}</p>", "${(canAccess('orcamentos')||canAccess('relatorios'))?`<div class=\"hr\"></div><p><strong>Valor vendido:</strong> ${money(j.value)} &nbsp; <strong>Custo estimado:</strong> ${money(j.cost)}</p>`:''}")

# Render access rules after every refresh.
index=index.replace("renderClients();renderVisits();renderCatalog();renderBudgets();renderJobs();renderJobMaterials();renderSchedule();renderWarranties();renderStock();renderPurchases();renderSales();renderFinanceTables();renderCash();renderDashboard();renderReports();renderEmployees();calcPrice();", "renderClients();renderVisits();renderCatalog();renderBudgets();renderJobs();renderJobMaterials();renderSchedule();renderWarranties();renderStock();renderPurchases();renderSales();renderFinanceTables();renderCash();renderDashboard();renderReports();renderEmployees();calcPrice();applyAccessUI();")

# ---------------- DATABASE SCHEMA ----------------
if 'CREATE TABLE IF NOT EXISTS user_access' not in schema:
    schema += """

CREATE TABLE IF NOT EXISTS user_access (
  user_id TEXT PRIMARY KEY,
  profile TEXT NOT NULL DEFAULT 'custom',
  permissions TEXT NOT NULL DEFAULT '[]',
  employee_id TEXT,
  own_jobs_only INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_user_access_employee ON user_access(employee_id);
"""

# Basic assertions before writing.
assert 'user_access' in worker
assert 'getDataForUser' in worker
assert 'const accessProfiles=' in index
assert 'saveEmployee(e,id)' in index
assert 'assignedEmployeeId' in index
worker_path.write_text(worker)
index_path.write_text(index)
schema_path.write_text(schema)
print('Serralheria Net V3 upgrade applied')
