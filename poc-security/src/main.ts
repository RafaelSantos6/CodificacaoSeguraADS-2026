import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module';
import { join } from 'path';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // Serve os arquivos estáticos do frontend interativo localizado na pasta /public
  app.useStaticAssets(join(__dirname, '..', 'public'));

  // Configura o Helmet para adicionar cabeçalhos HTTP de segurança,
  // incluindo uma política de Content-Security-Policy (CSP) que permite
  // a execução dos scripts e estilos internos do frontend ('self').
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          frameSrc: ["'self'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
    }),
  );

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`\n🚀 Servidor PoC de Segurança rodando em: http://localhost:${port}`);
  console.log(`📊 Painel de Testes disponível na raiz: http://localhost:${port}/\n`);
}
bootstrap();

