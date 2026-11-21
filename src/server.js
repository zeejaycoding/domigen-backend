import { createServer } from 'node:http'
import { createApp } from './app.js'
import { config } from './config.js'
import { closeDatabase, connectDatabase } from './db.js'
import { seedDatabase } from './seed.js'
import { setupRealtime } from './socket.js'

async function start() {
  await connectDatabase()
  await seedDatabase()

  const app = createApp()
  const server = createServer(app)
  const io = setupRealtime(server)
  app.set('io', io)

  server.listen(config.port, () => {
    console.log(`DOMIGEN API listening on http://127.0.0.1:${config.port}`)
    console.log(`MongoDB database: ${config.dbName}`)
  })

  const shutdown = async () => {
    console.log('Shutting down DOMIGEN API…')
    io.close()
    server.close()
    await closeDatabase()
    process.exit(0)
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

start().catch((error) => {
  console.error('Could not start DOMIGEN API:', error.message)
  process.exit(1)
})
