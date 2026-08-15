from pathlib import Path
p=Path('scripts/upgrade-v3.py')
s=p.read_text()
old="repl = needle + \"\\n    await env.DB.prepare('INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,\\'admin\\',?,NULL,0,?)').bind(id,JSON.stringify(ALL_MODULES),n).run();\""
new="repl = needle + '\\n    await env.DB.prepare(\"INSERT OR REPLACE INTO user_access(user_id,profile,permissions,employee_id,own_jobs_only,updated_at) VALUES(?,\\\'admin\\\',?,NULL,0,?)\").bind(id,JSON.stringify(ALL_MODULES),n).run();'"
if old in s:
    s=s.replace(old,new)
# Evitar duplicação da assinatura function esc ao substituir o bloco de usuários.
s=s.replace("\n\nfunction esc(\"\"\")\n\n# Restore function esc signature after replacement marker was consumed.\nworker = worker.replace('function esc(s=\\'\\') {', 'function esc(s=\\'\\') {', 1)\n", "\n\n\"\"\")\n")
p.write_text(s)
print('Gerador V3 corrigido')
