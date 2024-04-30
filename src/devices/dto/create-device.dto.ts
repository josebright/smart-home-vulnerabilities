import { IsNotEmpty, IsInt, Min } from 'class-validator';

export class CreateDeviceDto {
  @IsNotEmpty()
  readonly name: string;

  @IsInt()
  @Min(1)
  readonly categoryId: number;
}
