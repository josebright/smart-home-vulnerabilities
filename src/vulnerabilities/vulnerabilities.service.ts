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
        model: 'gpt-4',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.5,
        max_tokens: 100,
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

          const description =
            item.cve.descriptions.find((d) => d.lang === 'en')?.value ||
            item.cve.descriptions[0].value;

          const threatPrompt = `Threat is a negative or malicious event that can exploit a vulnerability. From this definition, without starting with the words; "The threat is..." or "In simple terms...". Be concised and state the threat in: "${description}"?`;
          const impactPrompt = `Be concised and in layman's terms without starting with the words: "The impact of the vulnerability..." or "The potential impact of the vulnerability..." or "In simple terms...", what is the potential impact in: "${description}"?`;
          const recommendationPrompt = `Be concised and in a layman's terms without starting with the "In simple terms..." or "I recommend..." words, provide recommendation for mitigating the threats with the description: ${description}.`;
          const affectedSystemPrompt = `Without starting with the words: "In simple terms..." or "The affected systems...", just only list the affected systems in: "${description}".`;
          const vulnerabilityPrompt = `Vulnerability is a lopehole or weakness in a device that can be exploited. From this definition, without starting with the words; "The vulnerability name is..." or "The device is vulnerable to...". Just give the name of the vulnerability in "${description}".`;

          const threats = await this.generateThreatAssessment(threatPrompt);
          const recommendations =
            await this.generateThreatAssessment(recommendationPrompt);
          const impact = await this.generateThreatAssessment(impactPrompt);
          const affectedSystem =
            await this.generateThreatAssessment(affectedSystemPrompt);
          const vulnerability =
            await this.generateThreatAssessment(vulnerabilityPrompt);

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
