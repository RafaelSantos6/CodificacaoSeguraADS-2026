import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { InjectRepository, InjectEntityManager } from '@nestjs/typeorm';
import { Repository, EntityManager } from 'typeorm';
import { JSDOM } from 'jsdom';
import DOMPurify from 'dompurify';
import { User } from './user.entity';

@Injectable()
export class AppService implements OnModuleInit {
  private readonly logger = new Logger(AppService.name);
  private readonly purify: ReturnType<typeof DOMPurify>;

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
        { username: 'admin', password: 'super_secret_admin_password_123' },
        { username: 'alice', password: 'alice_password_456' },
        { username: 'bob', password: 'bob_password_789' },
      ]);
      this.logger.log('Seed concluído: 3 usuários inseridos no SQLite in-memory.');
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
}
