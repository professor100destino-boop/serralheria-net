from pathlib import Path

p = Path('src/worker.js')
s = p.read_text(encoding='utf-8')

old_setup = '''async function setup(req, env) {
  const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  if ((count?.n || 0) > 0) return json({ error: 'already_initialized' }, 409);
  const body = await readBody(req); const username = String(body.username || '').trim().toLowerCase(); const password = body.password;
  if (!validUsername(username)) return json({ error: 'invalid_username' }, 400);
  if (!validPassword(password)) return json({ error: 'weak_password' }, 400);
  const salt = randomSalt(); const hash = await passwordHash(password, salt); const id = crypto.randomUUID(); const n = nowSec();
  await env.DB.prepare('INSERT INTO users(id,username,password_hash,salt,role,active,created_at,updated_at) VALUES(?,?,?,?,\\'admin\\',1,?,?)')
    .bind(id, username, hash, salt, n, n).run();
  return createSession(id, env);
}'''

new_setup = '''async function setup(req, env) {
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
}'''

if old_setup not in s:
    raise SystemExit('Bloco setup original não encontrado')
s = s.replace(old_setup, new_setup, 1)

old_handler = "f.onsubmit=async ev=>{ev.preventDefault();e.textContent='';const r=await fetch('${initialized?'/api/login':'/api/setup'}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});const j=await r.json().catch(()=>({}));if(r.ok)location.href='/';else e.textContent=j.error==='temporarily_blocked'?'Muitas tentativas. Tente novamente mais tarde.':j.error==='weak_password'?'Use uma senha com pelo menos 8 caracteres.':j.error==='invalid_username'?'Usuário inválido.':'Usuário ou senha inválidos.'};"
new_handler = "f.onsubmit=async ev=>{ev.preventDefault();e.textContent='';const r=await fetch('${initialized?'/api/login':'/api/setup'}',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});const j=await r.json().catch(()=>({}));if(r.ok){location.href='/';return}if(j.error==='already_initialized'){e.textContent='Administrador já criado. Atualizando…';setTimeout(()=>location.reload(),500);return}const msgs={temporarily_blocked:'Muitas tentativas. Tente novamente mais tarde.',weak_password:'Use uma senha com pelo menos 8 caracteres.',invalid_username:'Usuário inválido.',setup_crypto_error:'Erro ao proteger a senha. Tente novamente.',setup_db_error:'Erro ao gravar o administrador. Tente novamente.',setup_session_error:'Erro ao iniciar a sessão. O administrador não foi mantido; tente novamente.',server_error:'Erro interno no primeiro acesso. Tente novamente.'};e.textContent=msgs[j.error]||(initialized?'Usuário ou senha inválidos.':'Não foi possível criar o administrador.');};"

if old_handler not in s:
    raise SystemExit('Handler de login original não encontrado')
s = s.replace(old_handler, new_handler, 1)

p.write_text(s, encoding='utf-8')
print('Correção do primeiro acesso aplicada.')
