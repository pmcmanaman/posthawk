import { AppDataSource } from '../config/database'

export async function initializeDatabase() {
  try {
    await AppDataSource.initialize()
    console.log('Database connection established')
  } catch (error) {
    console.error('Error connecting to database:', error)
    process.exit(1)
  }
} 