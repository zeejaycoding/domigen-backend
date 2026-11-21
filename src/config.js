import 'dotenv/config'

const defaultOrigins = [
  'http://127.0.0.1:5173',
  'http://localhost:5173',
  'http://127.0.0.1:5174',
  'http://localhost:5174',
  'http://127.0.0.1:4173',
  'http://localhost:4173',
]

const configured = [process.env.FRONTEND_URL, process.env.ADMIN_URL]
  .filter(Boolean)
  .flatMap((url) => [url.replace(/\/$/, '')])

export const config = {
  port: Number(process.env.PORT || 4000),
  mongoUri: process.env.MONGODB_URI,
  dbName: process.env.MONGODB_DB || 'domigen',
  jwtSecret: process.env.JWT_SECRET || 'domigen-development-secret-change-me',
  adminEmail: 'admin@domigen.com',
  adminPassword: 'admin321',
  allowedOrigins: [...new Set([...defaultOrigins, ...configured])],
  allowAllOrigins: String(process.env.ALLOW_ALL_ORIGINS || 'false').toLowerCase() === 'true',
  frontendUrl: (process.env.FRONTEND_URL || defaultOrigins[0]).replace(/\/$/, ''),
  stripeSecretKey: process.env.STRIPE_SECRET_KEY || '',
  stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY || '',
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
  checkoutSuccessPath: process.env.CHECKOUT_SUCCESS_PATH || '/checkout/success',
  checkoutCancelPath: process.env.CHECKOUT_CANCEL_PATH || '/checkout/cancel',
}

if (!config.mongoUri) {
  throw new Error('Missing MONGODB_URI. Copy backend/.env.example to backend/.env and fill it in.')
}
