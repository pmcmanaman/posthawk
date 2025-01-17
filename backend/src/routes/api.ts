import express from 'express'
import { createUser, findUserByEmail, checkEmail } from '../controllers/userController'
import { createApiKey, listApiKeys, deactivateApiKey } from '../controllers/apiKeyController'
import { createTest, listTests, getTestById, updateTest } from '../controllers/testController'
import { authenticateUser } from '../middleware/auth'
import bcrypt from 'bcrypt'

const router = express.Router()

// Auth routes
router.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body
    const passwordHash = await bcrypt.hash(password, 10)
    const user = await createUser({ email, passwordHash, name })
    res.json({ id: user.id, email: user.email, name: user.name })
  } catch (error) {
    res.status(400).json({ error: 'Registration failed' })
  }
})

// API Key routes
router.post('/api-keys', authenticateUser, async (req, res) => {
  try {
    const apiKey = await createApiKey(req.user.id, req.body.name)
    res.json(apiKey)
  } catch (error) {
    res.status(400).json({ error: 'Could not create API key' })
  }
})

router.get('/api-keys', authenticateUser, async (req, res) => {
  try {
    const keys = await listApiKeys(req.user.id)
    res.json(keys)
  } catch (error) {
    res.status(400).json({ error: 'Could not fetch API keys' })
  }
})

router.delete('/api-keys/:id', authenticateUser, async (req, res) => {
  try {
    await deactivateApiKey(req.params.id, req.user.id)
    res.json({ success: true })
  } catch (error) {
    res.status(400).json({ error: 'Could not deactivate API key' })
  }
})

// Test routes
router.post('/tests', authenticateUser, async (req, res) => {
  try {
    const test = await createTest(req.body, req.user.id)
    res.json(test)
  } catch (error) {
    res.status(400).json({ error: 'Could not create test' })
  }
})

router.get('/tests', authenticateUser, async (req, res) => {
  try {
    const tests = await listTests(req.user.id)
    res.json(tests)
  } catch (error) {
    res.status(400).json({ error: 'Could not fetch tests' })
  }
})

router.get('/tests/:id', authenticateUser, async (req, res) => {
  try {
    const test = await getTestById(req.params.id, req.user.id)
    if (!test) {
      return res.status(404).json({ error: 'Test not found' })
    }
    res.json(test)
  } catch (error) {
    res.status(400).json({ error: 'Could not fetch test' })
  }
})

router.put('/tests/:id', authenticateUser, async (req, res) => {
  try {
    const test = await updateTest(req.params.id, req.user.id, req.body)
    res.json(test)
  } catch (error) {
    res.status(400).json({ error: 'Could not update test' })
  }
})

export default router
