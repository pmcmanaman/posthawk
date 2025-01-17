import { AppDataSource } from '../config/database'
import { Test } from '../models/Test'

const testRepository = AppDataSource.getRepository(Test)

export async function createTest(testData: Partial<Test>, userId: string) {
  const test = testRepository.create({
    ...testData,
    user: { id: userId }
  })
  await testRepository.save(test)
  return test
}

export async function listTests(userId: string) {
  return await testRepository.find({
    where: { user: { id: userId } },
    order: { createdAt: 'DESC' }
  })
}

export async function getTestById(id: string, userId: string) {
  return await testRepository.findOne({
    where: { id, user: { id: userId } }
  })
}

export async function updateTest(id: string, userId: string, updates: Partial<Test>) {
  const test = await testRepository.findOne({
    where: { id, user: { id: userId } }
  })
  
  if (!test) {
    throw new Error('Test not found')
  }
  
  Object.assign(test, updates)
  await testRepository.save(test)
  return test
} 