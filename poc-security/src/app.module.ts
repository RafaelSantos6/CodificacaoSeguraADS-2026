import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { User } from './user.entity';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'sqlite',
      database: ':memory:',
      entities: [User],
      synchronize: true,
      keepConnectionAlive: true,
    }),
    TypeOrmModule.forFeature([User]),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
