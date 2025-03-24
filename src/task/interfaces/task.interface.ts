import { CreateTaskDTO, UpdateTaskDTO } from "../dto/task.dto";

export interface Task {
  id: string;
  description: string;
  isDone: boolean;
  createdAt: Date;
}

export interface TaskService {
  findAll(): Promise<Task[]>;
  findById(id: string): Promise<Task>;
  create(createTaskDto: any): Promise<Task>;
  update(id: string, updateTaskDto: any): Promise<Task>;
  delete(id: string): Promise<void>;
}
