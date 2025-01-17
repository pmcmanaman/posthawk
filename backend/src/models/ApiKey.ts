import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { User } from './User'

@Entity()
export class ApiKey {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column()
  key: string

  @Column({ nullable: true })
  name: string

  @Column({ default: true })
  isActive: boolean

  @ManyToOne(() => User, user => user.apiKeys)
  user: User

  @CreateDateColumn()
  createdAt: Date

  @UpdateDateColumn()
  updatedAt: Date

  @Column({ nullable: true })
  lastUsedAt: Date
} 