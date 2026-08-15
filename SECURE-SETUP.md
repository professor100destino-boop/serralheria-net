# Serralheria Net 2.0 — Login e Banco Central

Esta versão usa Cloudflare Workers + D1 para proteger o aplicativo e centralizar os dados.

## Segurança implementada

- Login obrigatório antes de entregar a tela principal.
- Senhas derivadas com PBKDF2/SHA-256 e salt aleatório; a senha em texto puro não é armazenada.
- Sessão em cookie HttpOnly + Secure + SameSite=Strict.
- Sessão com validade de 8 horas.
- Bloqueio temporário após repetidas tentativas de login inválidas.
- Perfis Administrador e Funcionário.
- Administração de usuários em `/admin-users`.
- Banco central D1 para o estado do sistema.
- Controle de versão para avisar quando outro aparelho alterou os dados.
- Service Worker não mantém a tela administrativa em cache offline.

## Primeiro acesso

Quando ainda não existir nenhum usuário, o próprio endereço do sistema mostra a tela “Primeiro acesso”. O primeiro usuário criado torna-se Administrador.

## Banco

O arquivo `schema.sql` contém a estrutura do D1. O Worker também executa `CREATE TABLE IF NOT EXISTS`, evitando quebra no primeiro acesso.

## Publicação Cloudflare

1. Criar um banco D1 chamado `serralheria-net-db`.
2. Copiar o `database_id` retornado pela Cloudflare.
3. Copiar `wrangler.secure.example.jsonc` para `wrangler.jsonc` e substituir `SUBSTITUIR_PELO_ID_DO_D1`.
4. Aplicar `schema.sql` ao D1.
5. Fazer deploy do Worker.

Com Wrangler autenticado:

```bash
npx wrangler d1 create serralheria-net-db
npx wrangler d1 execute serralheria-net-db --remote --file=./schema.sql
npx wrangler deploy
```

## Dados atuais

A versão segura usa o mesmo formato JSON do sistema atual. Após o primeiro login, alterações passam a ser sincronizadas com o D1. Se houver dados importantes na versão antiga do GitHub Pages, exporte o backup antes da migração e importe-o na versão segura.
