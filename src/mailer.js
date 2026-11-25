import nodemailer from 'nodemailer'
import { config } from './config.js'
import { getSettings } from './repository.js'

export function emailConfigured() {
  return Boolean(config.smtpHost && config.smtpUser && config.smtpPass && config.smtpFrom)
}

function createTransport() {
  return nodemailer.createTransport({
    host: config.smtpHost,
    port: config.smtpPort,
    secure: config.smtpSecure,
    auth: {
      user: config.smtpUser,
      pass: config.smtpPass,
    },
  })
}

export async function sendPasswordResetEmail({ to, name, token }) {
  if (!emailConfigured()) {
    throw new Error('Password reset email is not configured on the server.')
  }

  const settings = await getSettings()
  const siteName = settings.name || 'DOMIGEN'
  const minutes = Number.isFinite(config.resetTokenTtlMinutes)
    ? Math.max(1, config.resetTokenTtlMinutes)
    : 30
  const link = `${config.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`
  const greeting = name ? `Hi ${name},` : 'Hi,'

  await createTransport().sendMail({
    from: config.smtpFrom,
    to,
    subject: `Reset your ${siteName} password`,
    text: [
      greeting,
      '',
      `Use the link below to choose a new ${siteName} password. It expires in ${minutes} minutes.`,
      link,
      '',
      'If you did not request this, you can ignore this email.',
    ].join('\n'),
    html: `
      <p>${greeting}</p>
      <p>Use the button below to choose a new ${siteName} password. It expires in ${minutes} minutes.</p>
      <p><a href="${link}" style="background:#06a7ea;color:#fff;padding:12px 20px;text-decoration:none;border-radius:3px;display:inline-block">Reset password</a></p>
      <p>If you did not request this, you can ignore this email.</p>
    `,
  })
}
