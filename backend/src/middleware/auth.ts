import { Request, Response, NextFunction } from 'express'
import { findUserByEmail } from '../controllers/userController'
import jwt from 'jsonwebtoken'

declare global {
  namespace Express {
    interface Request {
      user?: { id: string; email: string }
    }
  }
}

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key'

export async function authenticateUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization
  
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' })
  }

  const token = authHeader.split(' ')[1]
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { id: string; email: string }
    const user = await findUserByEmail(decoded.email)
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' })
    }
    
    req.user = { id: user.id, email: user.email }
    next()
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' })
  }
} 