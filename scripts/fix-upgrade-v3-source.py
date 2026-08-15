from pathlib import Path
p=Path('scripts/upgrade-v3.py')
s=p.read_text()
old="repl = needle + \"\\n    await env.DB.prepare('INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,\\'admin\\',?,NULL,0,?)').bind(id,JSON.stringify(ALL_MODULES),n).run();\""
new="repl = needle + '\\n    await env.DB.prepare(\"INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,\\\'admin\\\',?,NULL,0,?)\").bind(id,JSON.stringify(ALL_MODULES),n).run();'"
if old not in s:
    raise SystemExit('Trecho alvo do gerador V3 não encontrado')
p.write_text(s.replace(old,new))
print('Gerador V3 corrigido')
