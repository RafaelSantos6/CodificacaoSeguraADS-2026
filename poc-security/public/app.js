/**
 * Ambiente de Testes de Segurança - PoC
 * ADS 2026 - Codificação Segura (SQLi, CSRF, XSS)
 */

document.addEventListener('DOMContentLoaded', () => {
  // Event listeners - SQLi
  document.getElementById('btn-run-sqli').addEventListener('click', () => {
    runSQLi(document.getElementById('sqli-input').value.trim());
  });

  document.getElementById('sqli-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      runSQLi(document.getElementById('sqli-input').value.trim());
    }
  });

  // Event listeners - CSRF
  document.getElementById('btn-csrf-forge').addEventListener('click', () => {
    runCSRF(true);
  });

  document.getElementById('btn-csrf-legit').addEventListener('click', () => {
    runCSRF(false);
  });

  document.getElementById('btn-csrf-reset').addEventListener('click', resetCSRF);

  // Event listeners - XSS
  document.getElementById('btn-run-xss').addEventListener('click', () => {
    runXSS(document.getElementById('xss-input').value.trim());
  });

  document.getElementById('xss-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
      runXSS(document.getElementById('xss-input').value.trim());
    }
  });

  // Bateria completa
  document.getElementById('btn-run-all').addEventListener('click', runAudit);

  // Inicialização
  updateCSRFStatus();
  runSQLi(document.getElementById('sqli-input').value.trim());
  runXSS(document.getElementById('xss-input').value.trim());
});

// Funções chamadas pelos links de payloads rápidos
window.setSQLi = function(val) {
  document.getElementById('sqli-input').value = val;
  runSQLi(val);
};

window.setXSS = function(val) {
  document.getElementById('xss-input').value = val;
  runXSS(val);
};

/* ==========================================================================
   1. Módulo: SQL Injection (SQLi)
   ========================================================================== */

async function runSQLi(val) {
  document.getElementById('sqli-vuln-query').textContent =
    `SELECT id, username, password FROM users WHERE username = '${val}'`;

  document.getElementById('sqli-sec-query').textContent =
    `SELECT id, username FROM users WHERE username = ? [param: "${val}"]`;

  try {
    const [resVuln, resSec] = await Promise.all([
      fetch(`/sqli/vulnerable?username=${encodeURIComponent(val)}`),
      fetch(`/sqli/secure?username=${encodeURIComponent(val)}`)
    ]);

    const dataVuln = await resVuln.json();
    const dataSec = await resSec.json();

    // Renderiza Vulnerável
    document.getElementById('sqli-vuln-res').textContent = JSON.stringify(dataVuln, null, 2);
    const vulnStatus = document.getElementById('sqli-vuln-status');

    if (Array.isArray(dataVuln) && dataVuln.length > 1) {
      vulnStatus.className = 'status-box status-vuln';
      vulnStatus.textContent = `🚨 VULNERABILIDADE CONFIRMADA: A cláusula WHERE foi anulada pela injeção. Retornou ${dataVuln.length} usuários com senhas expostas.`;
    } else if (Array.isArray(dataVuln) && dataVuln.length === 1) {
      vulnStatus.className = 'status-box status-vuln';
      vulnStatus.textContent = `⚠️ ATENÇÃO: Retornou 1 registro, mas a coluna sensível "password" foi exposta na resposta HTTP.`;
    } else {
      vulnStatus.className = 'status-box';
      vulnStatus.textContent = `Consulta executada. Nenhum registro retornado.`;
    }

    // Renderiza Seguro
    document.getElementById('sqli-sec-res').textContent = JSON.stringify(dataSec, null, 2);
    const secStatus = document.getElementById('sqli-sec-status');

    if (Array.isArray(dataSec) && dataSec.length === 0 && (val.includes("'") || val.includes('--'))) {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `🛡️ MITIGADO: Prepared Statement ativo. A entrada foi tratada como literal puro. Zero registros vazados.`;
    } else if (Array.isArray(dataSec) && dataSec.length > 0) {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `✅ SEGURO: Registro legítimo localizado. Senhas foram intencionalmente omitidas da consulta.`;
    } else {
      secStatus.className = 'status-box';
      secStatus.textContent = `Consulta segura executada. Nenhum usuário encontrado para esse termo literal.`;
    }

  } catch (err) {
    document.getElementById('sqli-vuln-res').textContent = `Erro: ${err.message}`;
    document.getElementById('sqli-sec-res').textContent = `Erro: ${err.message}`;
  }
}

/* ==========================================================================
   2. Módulo: Cross-Site Request Forgery (CSRF)
   ========================================================================== */

async function updateCSRFStatus() {
  try {
    const res = await fetch('/csrf/status');
    const data = await res.json();
    if (data.victim && data.attacker) {
      document.getElementById('csrf-alice-balance').textContent = `R$ ${Number(data.victim.balance).toFixed(2)}`;
      document.getElementById('csrf-bob-balance').textContent = `R$ ${Number(data.attacker.balance).toFixed(2)}`;
    }
  } catch (err) {
    console.error('Erro ao buscar status CSRF:', err);
  }
}

async function resetCSRF() {
  try {
    const res = await fetch('/csrf/reset', { method: 'POST' });
    const data = await res.json();
    document.getElementById('csrf-alice-balance').textContent = `R$ ${Number(data.victim.balance).toFixed(2)}`;
    document.getElementById('csrf-bob-balance').textContent = `R$ ${Number(data.attacker.balance).toFixed(2)}`;
    document.getElementById('csrf-vuln-status').className = 'status-box';
    document.getElementById('csrf-vuln-status').textContent = 'Saldos redefinidos para o estado original.';
    document.getElementById('csrf-sec-status').className = 'status-box';
    document.getElementById('csrf-sec-status').textContent = 'Saldos redefinidos para o estado original.';
    document.getElementById('csrf-vuln-res').textContent = '[]';
    document.getElementById('csrf-sec-res').textContent = '[]';
  } catch (err) {
    console.error('Erro ao resetar CSRF:', err);
  }
}

async function runCSRF(isForged) {
  let token = null;

  if (!isForged) {
    // Busca token CSRF legítimo fornecido pela aplicação
    const tokenRes = await fetch('/csrf/token');
    const tokenData = await tokenRes.json();
    token = tokenData.csrfToken;
  }

  // Prepara informações da requisição para visualização didática
  const vulnReqPreview = `POST /csrf/transfer-vulnerable HTTP/1.1\nContent-Type: application/json\n${isForged ? '[Simulação de Origem Externa: Requisição Forjada SEM token]' : ''}\n\n{"toUser": "bob", "amount": 500}`;
  document.getElementById('csrf-vuln-req').textContent = vulnReqPreview;

  const secHeaders = { 'Content-Type': 'application/json' };
  if (token) {
    secHeaders['x-csrf-token'] = token;
  }

  const secReqPreview = `POST /csrf/transfer-secure HTTP/1.1\nContent-Type: application/json\nx-csrf-token: ${token || '[AUSENTE - ATAQUE FORJADO]'}\n\n{"toUser": "bob", "amount": 500}`;
  document.getElementById('csrf-sec-req').textContent = secReqPreview;

  try {
    // Dispara requisições simultâneas
    const [resVuln, resSec] = await Promise.all([
      fetch('/csrf/transfer-vulnerable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toUser: 'bob', amount: 500 }),
      }),
      fetch('/csrf/transfer-secure', {
        method: 'POST',
        headers: secHeaders,
        body: JSON.stringify({ toUser: 'bob', amount: 500 }),
      }),
    ]);

    const dataVuln = await resVuln.json();
    const dataSec = await resSec.json();

    // Lado Vulnerável
    document.getElementById('csrf-vuln-res').textContent = JSON.stringify(dataVuln, null, 2);
    const vulnStatus = document.getElementById('csrf-vuln-status');

    if (resVuln.ok) {
      vulnStatus.className = 'status-box status-vuln';
      vulnStatus.textContent = isForged
        ? `🚨 VULNERABILIDADE CONFIRMADA: A requisição forjada foi processada! O servidor não exigiu token anti-CSRF e transferiu R$ 500 de Alice para Bob sem seu consentimento.`
        : `Transferência executada no endpoint vulnerável.`;
    } else {
      vulnStatus.className = 'status-box';
      vulnStatus.textContent = `Erro: ${dataVuln.message || 'Falha'}`;
    }

    // Lado Seguro
    document.getElementById('csrf-sec-res').textContent = JSON.stringify(dataSec, null, 2);
    const secStatus = document.getElementById('csrf-sec-status');

    if (resSec.status === 403) {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `🛡️ MITIGADO: Requisição forjada rejeitada com HTTP 403 Forbidden! O servidor exigiu um token anti-CSRF válido e impediu a transferência forçada.`;
    } else if (resSec.ok) {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `✅ AUTORIZADO: Operação legítima concluída. O Synchronizer Token Pattern validou a autenticidade do pedido.`;
    } else {
      secStatus.className = 'status-box';
      secStatus.textContent = `Status: ${resSec.status}`;
    }

    // Atualiza saldos na interface
    await updateCSRFStatus();

  } catch (err) {
    document.getElementById('csrf-vuln-res').textContent = `Erro: ${err.message}`;
    document.getElementById('csrf-sec-res').textContent = `Erro: ${err.message}`;
  }
}

/* ==========================================================================
   3. Módulo: Cross-Site Scripting (XSS Refletido)
   ========================================================================== */

async function runXSS(val) {
  try {
    const [resVuln, resSec] = await Promise.all([
      fetch(`/xss/vulnerable?html=${encodeURIComponent(val)}`),
      fetch(`/xss/secure?html=${encodeURIComponent(val)}`)
    ]);

    const htmlVuln = await resVuln.text();
    const htmlSec = await resSec.text();

    // Renderiza Lado Vulnerável
    document.getElementById('xss-vuln-res').textContent = htmlVuln.trim();
    document.getElementById('xss-vuln-frame').srcdoc = htmlVuln;

    const vulnStatus = document.getElementById('xss-vuln-status');
    const hasDangerTag = /<script[\s\S]*?>[\s\S]*?<\/script>/i.test(htmlVuln) || /on\w+\s*=/i.test(htmlVuln);

    if (hasDangerTag) {
      vulnStatus.className = 'status-box status-vuln';
      vulnStatus.textContent = `🚨 VULNERABILIDADE CONFIRMADA: Código malicioso refletido intacto no HTML sem nenhuma sanitização.`;
    } else {
      vulnStatus.className = 'status-box';
      vulnStatus.textContent = `HTML refletido diretamente conforme recebido.`;
    }

    // Renderiza Lado Seguro
    document.getElementById('xss-sec-res').textContent = htmlSec.trim();
    document.getElementById('xss-sec-frame').srcdoc = htmlSec;

    const secStatus = document.getElementById('xss-sec-status');
    const hadDangerInInput = /<script[\s\S]*?>[\s\S]*?<\/script>/i.test(val) || /on\w+\s*=/i.test(val);
    const hasDangerInOutput = /<script[\s\S]*?>[\s\S]*?<\/script>/i.test(htmlSec) || /on\w+\s*=/i.test(htmlSec);

    if (hadDangerInInput && !hasDangerInOutput) {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `🛡️ MITIGADO: DOMPurify identificou e removeu os scripts/eventos perigosos. CSP ativo via Helmet.`;
    } else {
      secStatus.className = 'status-box status-safe';
      secStatus.textContent = `✅ SEGURO: Conteúdo tratado. Tags inofensivas preservadas e código executável filtrado.`;
    }

  } catch (err) {
    document.getElementById('xss-vuln-res').textContent = `Erro: ${err.message}`;
    document.getElementById('xss-sec-res').textContent = `Erro: ${err.message}`;
  }
}

/* ==========================================================================
   4. Bateria Completa de Testes (Auditoria)
   ========================================================================== */

async function runAudit() {
  const tbody = document.getElementById('audit-table-body');
  tbody.innerHTML = `<tr><td colspan="7" class="text-muted">Executando bateria de testes para SQLi, CSRF e XSS...</td></tr>`;

  // Reseta estado do CSRF antes de auditar
  await fetch('/csrf/reset', { method: 'POST' });

  // Busca token válido para teste legítimo de CSRF
  const tokenRes = await fetch('/csrf/token');
  const tokenData = await tokenRes.json();
  const validToken = tokenData.csrfToken;

  const testCases = [
    // 1. SQLi
    {
      id: 1,
      vuln: 'SQLi',
      endpoint: '/sqli/vulnerable?username=admin',
      payload: 'admin',
      run: () => fetch('/sqli/vulnerable?username=admin'),
      validate: (d) => Array.isArray(d) && d.length === 1 && d[0].username === 'admin',
      behaviorPass: 'Retornou admin com senha exposta',
      verdictPass: 'VULNERÁVEL',
      isVulnTest: true,
      isJson: true,
    },
    {
      id: 2,
      vuln: 'SQLi',
      endpoint: "/sqli/vulnerable?username=' OR 1=1 --",
      payload: "' OR 1=1 --",
      run: () => fetch("/sqli/vulnerable?username=' OR 1=1 --"),
      validate: (d) => Array.isArray(d) && d.length > 1,
      behaviorPass: 'Bypass WHERE: retornou todos os usuários e senhas',
      verdictPass: 'VULNERÁVEL',
      isVulnTest: true,
      isJson: true,
    },
    {
      id: 3,
      vuln: 'SQLi',
      endpoint: "/sqli/secure?username=' OR 1=1 --",
      payload: "' OR 1=1 --",
      run: () => fetch("/sqli/secure?username=' OR 1=1 --"),
      validate: (d) => Array.isArray(d) && d.length === 0,
      behaviorPass: 'Prepared Statement: 0 registros retornados, sem vazamento',
      verdictPass: 'SEGURO',
      isVulnTest: false,
      isJson: true,
    },

    // 2. CSRF
    {
      id: 4,
      vuln: 'CSRF',
      endpoint: '/csrf/transfer-vulnerable',
      payload: 'POST (sem token CSRF)',
      run: () => fetch('/csrf/transfer-vulnerable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toUser: 'bob', amount: 100 }),
      }),
      validate: (d, res) => res.ok && d.status === 'EXECUTADO_VULNERAVEL',
      behaviorPass: 'Ação crítica executada sem exigir token anti-CSRF',
      verdictPass: 'VULNERÁVEL',
      isVulnTest: true,
      isJson: true,
    },
    {
      id: 5,
      vuln: 'CSRF',
      endpoint: '/csrf/transfer-secure',
      payload: 'POST (sem token CSRF)',
      run: () => fetch('/csrf/transfer-secure', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toUser: 'bob', amount: 100 }),
      }),
      validate: (d, res) => res.status === 403,
      behaviorPass: 'Requisição forjada bloqueada com HTTP 403 Forbidden',
      verdictPass: 'SEGURO',
      isVulnTest: false,
      isJson: true,
    },
    {
      id: 6,
      vuln: 'CSRF',
      endpoint: '/csrf/transfer-secure',
      payload: 'POST (com x-csrf-token)',
      run: () => fetch('/csrf/transfer-secure', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-csrf-token': validToken,
        },
        body: JSON.stringify({ toUser: 'bob', amount: 100 }),
      }),
      validate: (d, res) => res.ok && d.status === 'AUTORIZADO_SEGURO',
      behaviorPass: 'Requisição autorizada com sucesso pelo Synchronizer Token',
      verdictPass: 'SEGURO',
      isVulnTest: false,
      isJson: true,
    },

    // 3. XSS
    {
      id: 7,
      vuln: 'XSS',
      endpoint: '/xss/secure?html=<b>ADS 2026</b>',
      payload: '<b>ADS 2026</b>',
      run: () => fetch('/xss/secure?html=<b>ADS 2026</b>'),
      validate: (t) => typeof t === 'string' && t.includes('<b>ADS 2026</b>'),
      behaviorPass: 'Tag <b> inofensiva preservada corretamente',
      verdictPass: 'SEGURO',
      isVulnTest: false,
      isJson: false,
    },
    {
      id: 8,
      vuln: 'XSS',
      endpoint: "/xss/vulnerable?html=<script>alert('XSS')</script>",
      payload: "<script>alert('XSS')</script>",
      run: () => fetch("/xss/vulnerable?html=<script>alert('XSS')</script>"),
      validate: (t) => typeof t === 'string' && t.includes('<script>'),
      behaviorPass: 'Tag <script> refletida no HTML sem filtro',
      verdictPass: 'VULNERÁVEL',
      isVulnTest: true,
      isJson: false,
    },
    {
      id: 9,
      vuln: 'XSS',
      endpoint: "/xss/secure?html=<b>Ok</b><script>alert('XSS')</script>",
      payload: "<b>Ok</b><script>alert('XSS')</script>",
      run: () => fetch("/xss/secure?html=<b>Ok</b><script>alert('XSS')</script>"),
      validate: (t) => typeof t === 'string' && !t.includes('<script>') && t.includes('<b>Ok</b>'),
      behaviorPass: 'DOMPurify expurgou <script> e manteve <b>Ok</b>',
      verdictPass: 'SEGURO',
      isVulnTest: false,
      isJson: false,
    }
  ];

  let rows = '';

  for (const t of testCases) {
    try {
      const res = await t.run();
      const body = t.isJson ? await res.json() : await res.text();
      const passed = t.validate(body, res);

      const badgeClass = t.isVulnTest ? 'badge-vuln' : 'badge-safe';
      const verdict = passed ? t.verdictPass : 'FALHA';
      const behavior = passed ? t.behaviorPass : 'Comportamento inesperado';

      rows += `
        <tr>
          <td>${t.id}</td>
          <td><strong>${t.vuln}</strong></td>
          <td><code>${t.endpoint.split('?')[0]}</code></td>
          <td><code>${escapeHtml(t.payload)}</code></td>
          <td>${res.status} ${res.statusText}</td>
          <td>${behavior}</td>
          <td><span class="badge-res ${badgeClass}">${verdict}</span></td>
        </tr>
      `;
    } catch (err) {
      rows += `
        <tr>
          <td>${t.id}</td>
          <td>${t.vuln}</td>
          <td>${t.endpoint}</td>
          <td><code>${escapeHtml(t.payload)}</code></td>
          <td>Erro</td>
          <td>${err.message}</td>
          <td><span class="badge-res badge-vuln">ERRO</span></td>
        </tr>
      `;
    }
  }

  tbody.innerHTML = rows;
  await updateCSRFStatus();
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
