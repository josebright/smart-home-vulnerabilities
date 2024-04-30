import {
  Controller,
  Get,
  Query,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { VulnerabilitiesService } from './vulnerabilities.service';
import { FetchVulnerabilitiesDto } from './dto/fetch-vulnerability.dto';

@Controller('vulnerabilities')
export class VulnerabilitiesController {
  constructor(
    private readonly vulnerabilitiesService: VulnerabilitiesService,
  ) {}

  @Get()
  @UsePipes(new ValidationPipe({ transform: true }))
  getAllVulnerabilities(
    @Query() fetchVulnerabilitiesDto: FetchVulnerabilitiesDto,
  ) {
    return this.vulnerabilitiesService.fetchVulnerabilities(
      fetchVulnerabilitiesDto,
    );
  }
}
