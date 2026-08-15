from pathlib import Path
p=Path('src/worker.js')
s=p.read_text(encoding='utf-8')
for old in ('const PBKDF2_ITERATIONS = 120000;','const PBKDF2_ITERATIONS = 20000;','const PBKDF2_ITERATIONS = 10000;'):
    if old in s:
        s=s.replace(old,'const PBKDF2_ITERATIONS = 20000;',1)
        break
else:
    raise SystemExit('Constante PBKDF2 não encontrada')
p.write_text(s,encoding='utf-8')
print('PBKDF2 ajustado para 20000 iterações.')
