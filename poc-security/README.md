# Guia de Execução e Testes da PoC de Segurança

Este documento explica como configurar e executar a aplicação em qualquer máquina, como os testes são realizados e exatamente o que está sendo testado.

---

## 1. Como rodar em qualquer máquina

### Pré-requisitos
- **Node.js** (versão 18 ou superior instalada): [nodejs.org](https://nodejs.org/)
- **npm** (incluso com o Node.js) ou outro gerenciador de pacotes compatível.

### Passo a passo para execução

1. **Acessar a pasta do projeto:**
   ```bash
   cd poc-security
   ```

2. **Instalar todas as dependências:**
   ```bash
   npm install
   ```

3. **Iniciar o servidor:**
   ```bash
   npm run start:dev
   ```

4. **Acesso à Aplicação:**
   - **Ambiente de Testes (Frontend):** Acesse diretamente no navegador: **`http://localhost:3000`**
   - O banco de dados SQLite em memória será iniciado e populado automaticamente com três usuários para teste: `admin`, `alice` e `bob`.

---

## 2. O que o projeto testa (Fundamentação Teórica)

O projeto testa três das vulnerabilidades web mais críticas do OWASP Top 10 e suas respectivas mitigações em TypeScript/NestJS:

1. **SQL Injection (SQLi — OWASP A03 / CWE-89):**
   - **Cenário vulnerável:** Concatenação direta de parâmetros de entrada na string SQL usando `entityManager.query()`.
   - **Cenário seguro:** Parametrização de consultas via Repository Pattern do TypeORM (`repository.find()`), delegando ao driver a criação de *Prepared Statements*.

2. **Cross-Site Request Forgery (CSRF — OWASP A01/A05 / CWE-352):**
   - **Cenário vulnerável:** Processamento de requisições de alteração de estado (transferência de saldo) sem validar consentimento ou token anti-CSRF, confiando apenas no envio automático de credenciais do navegador.
   - **Cenário seguro:** Implementação do padrão *Synchronizer Token Pattern*, exigindo a validação de um token anti-CSRF criptográfico (`x-csrf-token`), rejeitando requisições forjadas com `403 Forbidden`.

3. **Cross-Site Scripting (XSS Refletido — OWASP A03 / CWE-79):**
   - **Cenário vulnerável:** Retorno direto de dados fornecidos pelo usuário interpolados no corpo da resposta HTML sem sanitização.
   - **Cenário seguro:** Sanitização do conteúdo HTML utilizando `DOMPurify` (executado via `JSDOM` no backend) e defesa em profundidade através de cabeçalhos de *Content Security Policy* (CSP) configurados com o `Helmet`.

---

## 3. Ambiente de Testes (Frontend Simplificado)

Ao acessar `http://localhost:3000`, a aplicação disponibiliza um ambiente minimalista e direto com 4 seções:

1. **Seção SQL Injection:**
   - Entrada para parâmetros com atalhos de testes rápidos (`admin`, `' OR 1=1 --`, `' OR 'a'='a`).
   - Comparativo lado a lado com exibição da query gerada, alerta de vazamento de senhas no vulnerável e Prepared Statement no seguro.

2. **Seção CSRF (Transferência de Saldo):**
   - Demonstra a conta de Alice (vítima) com R$ 1.000,00 e Bob (atacante) com R$ 200,00.
   - Permite disparar uma **Requisição Forjada (Ataque CSRF — Sem Token)** ou uma **Requisição Legítima (Com Token)**.
   - Comprova a transferência forçada sem autorização no endpoint vulnerável vs o bloqueio com `403 Forbidden` no endpoint seguro.

3. **Seção XSS Refletido:**
   - Entrada com atalhos (`<b>`, `<script>`, `<img onerror>`).
   - Comparativo direto entre o HTML cru retornado e o HTML sanitizado pelo DOMPurify com renderização em *sandboxed iframes*.

4. **Bateria Completa de Testes (Auditoria em 1-Clique):**
   - Executa automaticamente 9 casos de teste cobrindo SQLi, CSRF e XSS, gerando uma matriz com status HTTP, comportamento observado e veredito final.

---

## 4. Testes Manuais via Terminal / Curl (Opcional)

Com o servidor em execução, você também pode chamar as rotas diretamente pelo terminal:

### Teste 1: SQL Injection (SQLi)
- **Vulnerável:** `curl -s "http://localhost:3000/sqli/vulnerable?username=%27%20OR%201=1%20--"`
- **Seguro:** `curl -s "http://localhost:3000/sqli/secure?username=%27%20OR%201=1%20--"`

### Teste 2: CSRF (Cross-Site Request Forgery)
- **Status das Contas:** `curl -s "http://localhost:3000/csrf/status"`
- **Ataque Forjado (Vulnerável):**
  ```bash
  curl -s -X POST http://localhost:3000/csrf/transfer-vulnerable \
    -H "Content-Type: application/json" \
    -d '{"toUser":"bob","amount":500}'
  ```
- **Ataque Forjado Bloqueado (Seguro):**
  ```bash
  curl -s -X POST http://localhost:3000/csrf/transfer-secure \
    -H "Content-Type: application/json" \
    -d '{"toUser":"bob","amount":500}'
  # Retorna HTTP 403 Forbidden
  ```
- **Requisição Legítima com Token (Seguro):**
  ```bash
  curl -s -X POST http://localhost:3000/csrf/transfer-secure \
    -H "Content-Type: application/json" \
    -H "x-csrf-token: sec_token_csrf_ads_2026" \
    -d '{"toUser":"bob","amount":200}'
  ```

### Teste 3: XSS Refletido
- **Vulnerável:** `curl -s "http://localhost:3000/xss/vulnerable?html=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E"`
- **Seguro:** `curl -s "http://localhost:3000/xss/secure?html=%3Cb%3EOk%3C/b%3E%3Cscript%3Ealert(%27XSS%27)%3C/script%3E"`
