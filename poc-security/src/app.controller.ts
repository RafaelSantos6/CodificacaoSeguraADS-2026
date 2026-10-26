import { Controller, Get, Query, Header } from '@nestjs/common';
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
}
