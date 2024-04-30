import {
  Column,
  Entity,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Category } from 'src/category/entities/category.entity';
import { Vulnerability } from 'src/vulnerabilities/entities/vulnerability.entity';

@Entity({ name: 'smart_home_devices' })
export class Device {
  @PrimaryGeneratedColumn()
  id: number;

  @Column('text')
  name: string;

  @ManyToOne(() => Category, (category) => category.devices, {
    onDelete: 'CASCADE',
  })
  category: Category;

  @OneToMany(() => Vulnerability, (vulnerability) => vulnerability.device, {
    cascade: true,
  })
  vulnerabilities: Vulnerability[];
}
