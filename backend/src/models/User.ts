import { Entity, PrimaryGeneratedColumn, Column, OneToMany, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { ApiKey } from './ApiKey'
import { Test } from './Test'

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string

  @Column({ unique: true })
  email: string

  @Column()
  passwordHash: string

  @Column({ nullable: true })
  name: string

  @OneToMany(() => ApiKey, apiKey => apiKey.user)
  apiKeys: ApiKey[]

  @OneToMany(() => Test, test => test.user)
  tests: Test[]

  @CreateDateColumn()
  createdAt: Date

  @UpdateDateColumn()
  updatedAt: Date
} 