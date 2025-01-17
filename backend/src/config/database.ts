import { DataSource } from 'typeorm'
import path from 'path'
import { User } from '../models/User'
import { ApiKey } from '../models/ApiKey'
import { Test } from '../models/Test'

export const AppDataSource = new DataSource({
  type: 'sqlite',
  database: path.join(__dirname, '../../data/database.sqlite'),
  entities: [User, ApiKey, Test],
  synchronize: true, // Set to false in production
  logging: process.env.NODE_ENV === 'development'
}) 