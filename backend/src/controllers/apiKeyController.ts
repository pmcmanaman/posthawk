import { AppDataSource } from '../config/database'
import { ApiKey } from '../models/ApiKey'
import { User } from '../models/User'
import crypto from 'crypto'

const apiKeyRepository = AppDataSource.getRepository(ApiKey)

export async function createApiKey(userId: string, name?: string) {
  const key = crypto.randomBytes(32).toString('hex')
  
  const apiKey = apiKeyRepository.create({
    key,
    name,
    user: { id: userId },
    isActive: true
  })
  
  await apiKeyRepository.save(apiKey)
  return apiKey
}

export async function listApiKeys(userId: string) {
  return await apiKeyRepository.find({
    where: { user: { id: userId } },
    order: { createdAt: 'DESC' }
  })
}

export async function deactivateApiKey(id: string, userId: string) {
  const apiKey = await apiKeyRepository.findOne({
    where: { id, user: { id: userId } }
  })
  
  if (!apiKey) {
    throw new Error('API key not found')
  }
  
  apiKey.isActive = false
  await apiKeyRepository.save(apiKey)
} 