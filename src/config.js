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
  smtpHost: process.env.SMTP_HOST || '',
  smtpPort: Number(process.env.SMTP_PORT || 587),
  smtpSecure: String(process.env.SMTP_SECURE || 'false').toLowerCase() === 'true',
  smtpUser: process.env.SMTP_USER || '',
  smtpPass: process.env.SMTP_PASS || '',
  smtpFrom: process.env.SMTP_FROM || process.env.SMTP_USER || '',
  resetTokenTtlMinutes: Number(process.env.RESET_TOKEN_TTL_MINUTES || 30),
  sendgridApiKey: process.env.SENDGRID_API_KEY || '',
  // SendGrid requires a sender identity verified in your SendGrid account.
  emailFrom: process.env.SENDGRID_FROM || process.env.EMAIL_FROM || process.env.SMTP_FROM || process.env.SMTP_USER || '',
  verifyTokenTtlMinutes: Number(process.env.EMAIL_VERIFY_TTL_MINUTES || 60),
}

if (!config.mongoUri) {
  throw new Error('Missing MONGODB_URI. Copy backend/.env.example to backend/.env and fill it in.')
}
