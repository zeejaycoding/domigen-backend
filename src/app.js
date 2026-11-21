import cors from 'cors'
import express from 'express'
import { corsOrigin, errorHandler } from './middleware.js'
import routes from './routes.js'
import { handleStripeWebhook } from './stripe.js'

export function createApp() {
  const app = express()
  app.disable('x-powered-by')

  app.use(cors({ origin: corsOrigin, credentials: true }))

  // Stripe signs the raw request body. This must stay before express.json().
  app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), handleStripeWebhook)

  app.use(express.json({ limit: '15mb' }))

  app.get('/', (_req, res) => {
    res.json({ name: 'DOMIGEN API', docs: '/api/health' })
  })
  app.use('/api', routes)

  app.use(errorHandler)
  return app
}
