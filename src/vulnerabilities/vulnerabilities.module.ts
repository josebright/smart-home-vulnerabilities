import { Module } from '@nestjs/common';
import { HttpModule } from '@nestjs/axios';
import { TypeOrmModule } from '@nestjs/typeorm';
import { VulnerabilitiesService } from './vulnerabilities.service';
import { VulnerabilitiesController } from './vulnerabilities.controller';
import { Vulnerability } from './entities/vulnerability.entity';
import { Device } from 'src/devices/entities/device.entity';

@Module({
  imports: [HttpModule, TypeOrmModule.forFeature([Vulnerability, Device])],
  controllers: [VulnerabilitiesController],
  providers: [VulnerabilitiesService],
})
export class VulnerabilitiesModule {}
