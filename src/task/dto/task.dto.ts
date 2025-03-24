import { IsBoolean, IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class TaskDTO {
  readonly description: string;
  readonly isDone: boolean;
}

export class CreateTaskDTO {
  @IsNotEmpty()
  @IsString()
  readonly description: string;

  @IsBoolean()
  readonly isDone: boolean = false;
}

export class UpdateTaskDTO {
  @IsOptional()
  @IsString()
  readonly description?: string;

  @IsOptional()
  @IsBoolean()
  readonly isDone?: boolean;
}
