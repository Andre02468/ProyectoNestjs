import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

export type TaskDocument = TaskModel & Document;

@Schema({
  timestamps: true, // Esto añadirá automáticamente createdAt y updatedAt
  toJSON: {
    transform: (_, ret) => {
      ret.id = ret._id.toString();
      delete ret._id;
      delete ret.__v;
      return ret;
    }
  }
})
export class TaskModel {
  @Prop({ required: true })
  description: string;

  @Prop({ default: false })
  isDone: boolean;
}

export const TaskSchema = SchemaFactory.createForClass(TaskModel);