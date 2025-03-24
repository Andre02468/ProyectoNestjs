import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  Put,
} from '@nestjs/common';
import { CreateTaskDTO, UpdateTaskDTO } from './dto/task.dto';
import { Task } from './interfaces/task.interface';
import { TaskService } from './task.service';

@Controller('api/v1/tasks')
export class TaskController {
  constructor(private readonly taskService: TaskService) {}

  @Post() 
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createTaskDto: CreateTaskDTO): Promise<Task> {
    return this.taskService.create(createTaskDto);
  }

  @Get()
  async findAll(): Promise<Task[]> {
    return this.taskService.findAll();
  }

  @Get(':id')
  async findById(@Param('id') id: string): Promise<Task> {
    return this.taskService.findById(id);
  }

  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body() updateTaskDto: UpdateTaskDTO,
  ): Promise<Task> {
    return this.taskService.update(id, updateTaskDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    return this.taskService.delete(id);
  }
}
