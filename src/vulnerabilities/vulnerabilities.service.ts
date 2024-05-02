/* eslint-disable @typescript-eslint/no-var-requires */
import { Injectable, NotFoundException } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { firstValueFrom } from 'rxjs';
import { Vulnerability } from './entities/vulnerability.entity';
import { Device } from 'src/devices/entities/device.entity';
import { FetchVulnerabilitiesDto } from './dto/fetch-vulnerability.dto';
import OpenAI from 'openai';

require('dotenv').config();

@Injectable()
export class VulnerabilitiesService {
  private openAI;

  constructor(
    private httpService: HttpService,
    @InjectRepository(Vulnerability)
    private vulnerabilityRepository: Repository<Vulnerability>,
    @InjectRepository(Device)
    private deviceRepository: Repository<Device>,
  ) {
    const apiKey = process.env.OPENAI_API_KEY;
    this.openAI = new OpenAI({ apiKey: apiKey });
  }

  async generateThreatAssessment(prompt: string): Promise<string> {
    try {
      const response = await this.openAI.chat.completions.create({
        model: 'gpt-3.5-turbo',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.7,
        max_tokens: 50,
      });
      return response.choices[0].message.content;
    } catch (error) {
      return `Currently unable to generate text: ${error.message}`;
    }
  }

  async fetchVulnerabilities(fetchVulnerabilitiesDto: FetchVulnerabilitiesDto) {
    const device = await this.deviceRepository.findOne({
      where: { name: fetchVulnerabilitiesDto.keywordSearch },
    });
    if (!device) {
      throw new NotFoundException(
        `No device found with the name: ${fetchVulnerabilitiesDto.keywordSearch}`,
      );
    }

    function mapCvssMetrics(cvssMetric) {
      const defaults = {
        version: 'NONE',
        attackVector: 'NONE',
        attackComplexity: 'NONE',
        privilegesRequired: 'NONE',
        userInteraction: 'NONE',
        scope: 'NONE',
        confidentialityImpact: 'NONE',
        integrityImpact: 'NONE',
        availabilityImpact: 'NONE',
        baseScore: 0,
        baseSeverity: 'NONE',
        exploitabilityScore: 0,
        impactScore: 0,
      };

      const cvssData = cvssMetric.cvssData;

      if (cvssData.version.startsWith('3')) {
        return {
          version: cvssData.version || defaults.version,
          attackVector: cvssData.attackVector || defaults.attackVector,
          attackComplexity:
            cvssData.attackComplexity || defaults.attackComplexity,
          privilegesRequired:
            cvssData.privilegesRequired || defaults.privilegesRequired,
          userInteraction: cvssData.userInteraction || defaults.userInteraction,
          scope: cvssData.scope || defaults.scope,
          confidentialityImpact:
            cvssData.confidentialityImpact || defaults.confidentialityImpact,
          integrityImpact: cvssData.integrityImpact || defaults.integrityImpact,
          availabilityImpact:
            cvssData.availabilityImpact || defaults.availabilityImpact,
          baseScore: cvssData.baseScore || defaults.baseScore,
          baseSeverity: cvssData.baseSeverity || defaults.baseSeverity,
          exploitabilityScore:
            cvssMetric.exploitabilityScore || defaults.exploitabilityScore,
          impactScore: cvssMetric.impactScore || defaults.impactScore,
        };
      } else if (cvssData.version.startsWith('2')) {
        return {
          version: cvssData.version || defaults.version,
          attackVector: cvssData.accessVector || defaults.attackVector,
          attackComplexity:
            cvssData.accessComplexity || defaults.attackComplexity,
          privilegesRequired:
            cvssData.authentication || defaults.privilegesRequired,
          userInteraction: cvssMetric.userInteractionRequired
            ? 'REQUIRED'
            : 'NONE',
          confidentialityImpact:
            cvssData.confidentialityImpact || defaults.confidentialityImpact,
          integrityImpact: cvssData.integrityImpact || defaults.integrityImpact,
          availabilityImpact:
            cvssData.availabilityImpact || defaults.availabilityImpact,
          baseScore: cvssData.baseScore || defaults.baseScore,
          baseSeverity: cvssMetric.baseSeverity || defaults.baseSeverity,
          exploitabilityScore:
            cvssMetric.exploitabilityScore || defaults.exploitabilityScore,
          impactScore: cvssMetric.impactScore || defaults.impactScore,
        };
      } else {
        return defaults;
      }
    }

    const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

    try {
      const response = await firstValueFrom(
        this.httpService.get(url, {
          params: {
            keywordSearch: fetchVulnerabilitiesDto.keywordSearch,
          },
        }),
      );

      const fetchedVulnerabilities = response.data.vulnerabilities;

      const newVulnerabilities = [];

      for (const item of fetchedVulnerabilities) {
        const exists = await this.vulnerabilityRepository.findOne({
          where: { cveId: item.cve.id },
        });
        if (!exists) {
          const cveDetails = item.cve || {};
          const metricsDetails = cveDetails.metrics || {};
          const cvssMetricV3 =
            metricsDetails.cvssMetricV30 || metricsDetails.cvssMetricV31;
          const cvssMetricV2 = metricsDetails.cvssMetricV2;

          const allMetrics = [];
          // Process all CVSS v3 metrics
          cvssMetricV3?.forEach((cvssMetric) => {
            const mappedMetrics = mapCvssMetrics(cvssMetric);
            allMetrics.push(mappedMetrics);
          });
          // Process all CVSS v2 metrics
          cvssMetricV2?.forEach((cvssMetric) => {
            const mappedMetrics = mapCvssMetrics(cvssMetric);
            allMetrics.push(mappedMetrics);
          });

          const vulnerability =
            item.cve.descriptions.find((d) => d.lang === 'en')?.value ||
            item.cve.descriptions[0].value;

          const threatPrompt = `In layman's terms without using the 'in simple terms' words, provide the threat from the description: ${vulnerability}`;
          const impactPrompt = `In layman's terms without using the 'in simple terms' words, what is the potential impact of the vulnerability as described: ${vulnerability}`;
          const recommendationPrompt = `In layman's terms without using the 'in simple terms' words, provide recommendation for mitigating the threats with the description: ${vulnerability}`;
          const affectedSystemPrompt = `In layman's terms without using the 'in simple terms' words, list the affected systems from the description: ${vulnerability}`;

          const threats = await this.generateThreatAssessment(threatPrompt);
          const recommendations =
            await this.generateThreatAssessment(recommendationPrompt);
          const impact = await this.generateThreatAssessment(impactPrompt);
          const affectedSystem =
            await this.generateThreatAssessment(affectedSystemPrompt);

          if (!exists) {
            const newVuln = this.vulnerabilityRepository.create({
              cveId: item.cve.id,
              vulnerability,
              lastModified: item.cve.lastModified,
              vulnStatus: item.cve.vulnStatus,
              device: device,
              references: item.cve.references.map((reference) => reference.url),
              metrics: allMetrics,
              impact,
              affectedSystem,
              threats,
              recommendations,
            });
            newVulnerabilities.push(newVuln);
          }
        }
      }

      await this.vulnerabilityRepository.save(newVulnerabilities);
      return this.vulnerabilityRepository.find({
        where: { device: device },
        relations: ['device'],
      });
    } catch (error) {
      throw new Error(`Failed to fetch vulnerabilities: ${error.message}`);
    }
  }
}
