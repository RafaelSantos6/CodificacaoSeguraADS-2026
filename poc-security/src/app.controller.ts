import { Controller, Get, Post, Query, Body, Headers, Header, All } from '@nestjs/common';
import { AppService } from './app.service';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  // ==========================================
  // 1. ENDPOINTS DE SQL INJECTION (SQLi)
  // ==========================================

  @Get('sqli/vulnerable')
  async sqliVulnerable(@Query('username') username: string) {
    return this.appService.findUserVulnerable(username);
  }

  @Get('sqli/secure')
  async sqliSecure(@Query('username') username: string) {
    return this.appService.findUserSecure(username);
  }

  // ==========================================
  // 2. ENDPOINTS DE CROSS-SITE SCRIPTING (XSS)
  // ==========================================

  @Get('xss/vulnerable')
  @Header('Content-Type', 'text/html; charset=utf-8')
  xssVulnerable(@Query('html') html: string): string {
    return this.appService.renderHtmlVulnerable(html);
  }

  @Get('xss/secure')
  @Header('Content-Type', 'text/html; charset=utf-8')
  xssSecure(@Query('html') html: string): string {
    return this.appService.renderHtmlSecure(html);
  }

  // ==========================================
  // 3. ENDPOINTS DE CROSS-SITE REQUEST FORGERY (CSRF)
  // ==========================================

  @Get('csrf/status')
  async csrfStatus() {
    return this.appService.getCsrfStatus();
  }

  @Get('csrf/token')
  csrfToken() {
    return this.appService.getCsrfToken();
  }

  @Post('csrf/reset')
  async csrfReset() {
    return this.appService.resetCsrfBalances();
  }

  /**
   * [VULNERÁVEL A CSRF]
   * Executa a ação de transferência sem validar o token CSRF.
   * Suporta POST e GET para demonstrar forjamento via formulários ou links/imagens.
   */
  @All('csrf/transfer-vulnerable')
  async csrfTransferVulnerable(
    @Query('toUser') queryToUser?: string,
    @Query('amount') queryAmount?: string,
    @Body('toUser') bodyToUser?: string,
    @Body('amount') bodyAmount?: number,
  ) {
    const toUser = bodyToUser || queryToUser || 'bob';
    const amount = Number(bodyAmount || queryAmount || 500);
    return this.appService.transferVulnerable(toUser, amount);
  }

  /**
   * [SEGURO CONTRA CSRF]
   * Exige a presença do token CSRF válido no cabeçalho x-csrf-token ou no corpo da requisição.
   */
  @Post('csrf/transfer-secure')
  async csrfTransferSecure(
    @Headers('x-csrf-token') headerToken: string,
    @Body('toUser') toUser: string = 'bob',
    @Body('amount') amount: number = 500,
    @Body('_csrf') bodyToken?: string,
  ) {
    const token = headerToken || bodyToken;
    return this.appService.transferSecure(toUser, Number(amount || 500), token);
  }
}

