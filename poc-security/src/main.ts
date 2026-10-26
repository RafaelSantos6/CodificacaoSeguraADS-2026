import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Configura o Helmet para adicionar cabeçalhos HTTP de segurança,
  // incluindo uma política restritiva de Content-Security-Policy (CSP).
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"], // Bloqueia a execução de scripts inline não autorizados
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
    }),
  );

  await app.listen(3000);
}
bootstrap();
