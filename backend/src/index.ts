import 'reflect-metadata'
import express from 'express'
import { initializeDatabase } from './utils/initDatabase'
import apiRoutes from './routes/api'

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json())
app.use('/api', apiRoutes)

async function startServer() {
  await initializeDatabase()
  
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
  })
}

startServer().catch(console.error) 