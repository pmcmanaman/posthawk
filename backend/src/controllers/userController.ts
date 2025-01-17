import { AppDataSource } from '../config/database'
import { User } from '../models/User'

const userRepository = AppDataSource.getRepository(User)

export async function createUser(userData: Partial<User>) {
  const user = userRepository.create(userData)
  await userRepository.save(user)
  return user
}

export async function findUserByEmail(email: string) {
  return await userRepository.findOne({ where: { email } })
} 