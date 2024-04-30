import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Device } from './entities/device.entity';
import { Category } from 'src/category/entities/category.entity';
import { CreateDeviceDto } from './dto/create-device.dto';

@Injectable()
export class DevicesService {
  constructor(
    @InjectRepository(Device)
    private readonly deviceRepository: Repository<Device>,
    @InjectRepository(Category)
    private readonly categoryRepository: Repository<Category>,
  ) {}

  async create(createDeviceDto: CreateDeviceDto): Promise<Device> {
    // Check if the category exists
    const category = await this.categoryRepository.findOne({
      where: { id: createDeviceDto.categoryId },
    });
    if (!category) {
      throw new NotFoundException(
        `Category with ID ${createDeviceDto.categoryId} not found`,
      );
    }
    const device = this.deviceRepository.create({
      ...createDeviceDto,
      category: category,
    });
    return this.deviceRepository.save(device);
  }

  findAll(): Promise<Device[]> {
    return this.deviceRepository.find({
      relations: ['category', 'vulnerabilities'],
    });
  }

  async remove(id: number): Promise<void> {
    const result = await this.deviceRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`Device with ID ${id} not found`);
    }
  }
}
