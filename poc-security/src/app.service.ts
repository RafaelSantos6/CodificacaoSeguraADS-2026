import { Injectable, OnModuleInit, Logger, ForbiddenException } from '@nestjs/common';
import { InjectRepository, InjectEntityManager } from '@nestjs/typeorm';
import { Repository, EntityManager } from 'typeorm';
import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';
import { User } from './user.entity';

@Injectable()
export class AppService implements OnModuleInit {
  private readonly logger = new Logger(AppService.name);
  private readonly purify: ReturnType<typeof DOMPurify>;
  private readonly validCsrfToken = 'sec_token_csrf_ads_2026';

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectEntityManager()
    private readonly entityManager: EntityManager,
  ) {
    const window = new JSDOM('').window;
    this.purify = DOMPurify(window);
  }

  /**
   * Seed inicial do banco de dados SQLite em memória.
   */
  async onModuleInit() {
    const count = await this.userRepository.count();
    if (count === 0) {
      await this.userRepository.save([
        { username: 'admin', password: 'super_secret_admin_password_123', balance: 5000, email: 'admin@empresa.com' },
        { username: 'alice', password: 'alice_password_456', balance: 1000, email: 'alice@empresa.com' },
        { username: 'bob', password: 'bob_password_789', balance: 200, email: 'bob@empresa.com' },
      ]);
      this.logger.log('Seed concluído: 3 usuários inseridos no SQLite in-memory com saldos e emails.');
    }
  }

  /**
   * [VULNERÁVEL A SQL INJECTION]
   * Executa uma query SQL crua concatenando diretamente a entrada do usuário.
   */
  async findUserVulnerable(username: string): Promise<any> {
    const rawQuery = `SELECT id, username, password FROM users WHERE username = '${username}'`;
    this.logger.warn(`Executando query não parametrizada: ${rawQuery}`);
    return this.entityManager.query(rawQuery);
  }

  /**
   * [SEGURO CONTRA SQL INJECTION]
   * Utiliza o Repository Pattern do TypeORM com consultas parametrizadas (Prepared Statements).
   */
  async findUserSecure(username: string): Promise<User[]> {
    return this.userRepository.find({
      where: { username },
      select: ['id', 'username'], // Boas práticas: evita retornar o campo de senha
    });
  }

  /**
   * [VULNERÁVEL A XSS REFLETIDO]
   * Retorna o conteúdo enviado pelo usuário diretamente no HTML sem sanitização ou codificação.
   */
  renderHtmlVulnerable(input: string): string {
    return `
      <!DOCTYPE html>
      <html lang="pt-BR">
        <head><meta charset="UTF-8"><title>XSS Vulnerável</title></head>
        <body>
          <h1>Resultado da busca (Vulnerável):</h1>
          <div>Você pesquisou por: ${input || ''}</div>
        </body>
      </html>
    `;
  }

  /**
   * [SEGURO CONTRA XSS REFLETIDO]
   * Sanitiza o HTML de entrada com DOMPurify, removendo tags e atributos perigosos.
   */
  renderHtmlSecure(input: string): string {
    const sanitizedInput = this.purify.sanitize(input || '');
    return `
      <!DOCTYPE html>
      <html lang="pt-BR">
        <head><meta charset="UTF-8"><title>XSS Seguro</title></head>
        <body>
          <h1>Resultado da busca (Seguro):</h1>
          <div>Você pesquisou por: ${sanitizedInput}</div>
        </body>
      </html>
    `;
  }

  // ==========================================
  // 3. MÉTODOS DE CROSS-SITE REQUEST FORGERY (CSRF)
  // ==========================================

  /**
   * Retorna o status das contas da vítima (Alice) e do atacante (Bob).
   */
  async getCsrfStatus() {
    const alice = await this.userRepository.findOne({ where: { username: 'alice' } });
    const bob = await this.userRepository.findOne({ where: { username: 'bob' } });
    return {
      victim: { username: alice?.username, balance: alice?.balance, email: alice?.email },
      attacker: { username: bob?.username, balance: bob?.balance, email: bob?.email },
    };
  }

  /**
   * Retorna o token CSRF legítimo para ser usado em clientes autorizados (Synchronizer Token Pattern).
   */
  getCsrfToken() {
    return { csrfToken: this.validCsrfToken };
  }

  /**
   * Reseta os saldos para o estado inicial de demonstração.
   */
  async resetCsrfBalances() {
    await this.userRepository.update({ username: 'alice' }, { balance: 1000 });
    await this.userRepository.update({ username: 'bob' }, { balance: 200 });
    return this.getCsrfStatus();
  }

  /**
   * [VULNERÁVEL A CSRF]
   * Processa a transferência sem validar nenhum token anti-CSRF ou cabeçalho de consentimento.
   * Se o navegador enviar a requisição (mesmo vinda de outra aba/site malicioso), a transferência é aceita!
   */
  async transferVulnerable(toUser: string, amount: number) {
    const alice = await this.userRepository.findOne({ where: { username: 'alice' } });
    const recipient = await this.userRepository.findOne({ where: { username: toUser } });

    if (!alice || !recipient) {
      throw new Error('Usuário não encontrado.');
    }

    alice.balance -= amount;
    recipient.balance += amount;

    await this.userRepository.save([alice, recipient]);

    return {
      status: 'EXECUTADO_VULNERAVEL',
      message: `🚨 Transferência de R$ ${amount} de Alice para ${toUser} executada SEM validação de CSRF Token.`,
      balances: {
        alice: alice.balance,
        [toUser]: recipient.balance,
      },
    };
  }

  /**
   * [SEGURO CONTRA CSRF]
   * Exige a validação estrita de um Anti-CSRF Token (Synchronizer Token Pattern).
   * Requisições forjadas por sites de terceiros não possuem o token e são rejeitadas com 403 Forbidden.
   */
  async transferSecure(toUser: string, amount: number, providedToken?: string) {
    if (!providedToken || providedToken !== this.validCsrfToken) {
      throw new ForbiddenException({
        status: 'BLOQUEADO_CSRF',
        message: '🛡️ Ataque CSRF Bloqueado: Token anti-CSRF ausente ou inválido.',
      });
    }

    const alice = await this.userRepository.findOne({ where: { username: 'alice' } });
    const recipient = await this.userRepository.findOne({ where: { username: toUser } });

    if (!alice || !recipient) {
      throw new Error('Usuário não encontrado.');
    }

    alice.balance -= amount;
    recipient.balance += amount;

    await this.userRepository.save([alice, recipient]);

    return {
      status: 'AUTORIZADO_SEGURO',
      message: `✅ Transferência de R$ ${amount} de Alice para ${toUser} AUTORIZADA com Token CSRF válido.`,
      balances: {
        alice: alice.balance,
        [toUser]: recipient.balance,
      },
    };
  }
}

