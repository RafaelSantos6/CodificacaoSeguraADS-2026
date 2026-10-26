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
   O projeto já contém o `package.json` configurado. Basta executar:
   ```bash
   npm install
   ```

3. **Iniciar o servidor:**
   ```bash
   npm run start:dev
   ```

4. **Verificação de inicialização:**
   - A aplicação estará disponível em: `http://localhost:3000`
   - O banco de dados SQLite em memória será iniciado e populado automaticamente com três usuários para teste: `admin`, `alice` e `bob`.

---

## 2. O que o projeto testa

O projeto testa duas das vulnerabilidades web mais críticas do OWASP Top 10 e suas respectivas mitigações em TypeScript/NestJS:

1. **SQL Injection (SQLi):**
   - **Cenário vulnerável:** Concatenação direta de parâmetros de entrada na string SQL usando `entityManager.query()`.
   - **Cenário seguro:** Parametrização de consultas via Repository Pattern do TypeORM (`repository.find()`), delegando ao driver a criação de *Prepared Statements*.

2. **Cross-Site Scripting (XSS Refletido):**
   - **Cenário vulnerável:** Retorno direto de dados fornecidos pelo usuário interpolados no corpo da resposta HTML sem sanitização.
   - **Cenário seguro:** Sanitização do conteúdo HTML utilizando `DOMPurify` (executado via `JSDOM` no backend) e defesa em profundidade através de cabeçalhos de *Content Security Policy* (CSP) configurados com o `Helmet`.

---

## 3. Como os testes funcionam

Com o servidor em execução (`npm run start:dev`), abra o navegador ou utilize o terminal (curl/Postman) para chamar as rotas:

### Teste 1: SQL Injection (SQLi)

- **Endpoint Vulnerável:**
  - **Requisição normal:**
    `http://localhost:3000/sqli/vulnerable?username=admin`
    *(Retorna os dados do usuário `admin`, incluindo senha).*
  - **Comportamento sob injeção de metacaracteres:**
    `http://localhost:3000/sqli/vulnerable?username=' OR 1=1 --`
    *(A lógica SQL é subvertida pela concatenação. A cláusula `WHERE` se torna sempre verdadeira e retorna **todos os usuários da tabela** e suas senhas).*

- **Endpoint Seguro:**
  - **Requisição normal:**
    `http://localhost:3000/sqli/secure?username=admin`
    *(Retorna apenas os campos seguros `id` e `username` do usuário `admin`).*
  - **Comportamento sob injeção de metacaracteres:**
    `http://localhost:3000/sqli/secure?username=' OR 1=1 --`
    *(A entrada é tratada estritamente como dado literal pela consulta parametrizada. O banco busca literalmente um usuário com esse nome, resultando em `[]` vazio e sem vazamento de dados).*

---

### Teste 2: Cross-Site Scripting (XSS Refletido)

- **Endpoint Vulnerável:**
  - **URL de teste:**
    `http://localhost:3000/xss/vulnerable?html=<script>alert('XSS')</script>`
  - **Resultado:** O texto enviado na querystring é injetado diretamente no DOM HTML retornado. Se inspecionado ou renderizado, a tag `<script>` permanece no documento sem qualquer filtro.

- **Endpoint Seguro:**
  - **URL de teste:**
    `http://localhost:3000/xss/secure?html=<b>Texto Seguro</b><script>alert('XSS')</script>`
  - **Resultado:** O `DOMPurify` processa o conteúdo antes do envio. Tags de formatação inofensivas como `<b>` são mantidas, enquanto qualquer tag perigosa como `<script>` é completamente removida. Adicionalmente, o cabeçalho `Content-Security-Policy` aplicado via `Helmet` impede a execução de scripts inline não autorizados no navegador.
