import { Column, Entity, OneToMany, PrimaryGeneratedColumn } from 'typeorm';
import { Device } from 'src/devices/entities/device.entity';

@Entity({ name: 'smart_home_categories' })
export class Category {
  @PrimaryGeneratedColumn()
  id: number;

  @Column('text')
  name: string;

  @OneToMany(() => Device, (device) => device.category, { cascade: true })
  devices: Device[];
}
