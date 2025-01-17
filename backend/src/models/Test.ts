import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { User } from './User'

@Entity()
export class Test {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column()
  name: string

  @Column('text')
  description: string

  @Column('json')
  testData: object

  @Column('json')
  expectedResults: object

  @Column({ default: true })
  isActive: boolean

  @ManyToOne(() => User, user => user.tests)
  user: User

  @CreateDateColumn()
  createdAt: Date

  @UpdateDateColumn()
  updatedAt: Date

  @Column({ nullable: true })
  lastRunAt: Date
} 