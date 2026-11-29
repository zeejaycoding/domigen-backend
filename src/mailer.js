import nodemailer from 'nodemailer'
import { config } from './config.js'
import { getSettings } from './repository.js'

function sendgridConfigured() {
  return Boolean(config.sendgridApiKey && config.emailFrom)
}

function smtpConfigured() {
  return Boolean(config.smtpHost && config.smtpUser && config.smtpPass && config.smtpFrom)
}

export function emailConfigured() {
  return sendgridConfigured() || smtpConfigured()
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

async function sendWithSendGrid({ to, siteName, subject, text, html }) {
  const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.sendgridApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: config.emailFrom, name: siteName },
      subject,
      content: [
        { type: 'text/plain', value: text },
        { type: 'text/html', value: html },
      ],
    }),
  })

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300)
    throw new Error(`SendGrid rejected the email (${response.status}): ${detail}`)
  }
}

async function sendMail(message) {
  if (!emailConfigured()) {
    throw new Error('Email delivery is not configured on the server.')
  }
  if (sendgridConfigured()) {
    return sendWithSendGrid(message)
  }
  return createTransport().sendMail({
    from: config.smtpFrom,
    to: message.to,
    subject: message.subject,
    text: message.text,
    html: message.html,
  })
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

async function siteName() {
  const settings = await getSettings()
  return settings.name || 'DOMIGEN'
}

function greetingFor(name) {
  return name ? `Hi ${name},` : 'Hi,'
}

export async function sendPasswordResetEmail({ to, name, token }) {
  const site = await siteName()
  const minutes = Number.isFinite(config.resetTokenTtlMinutes)
    ? Math.max(1, config.resetTokenTtlMinutes)
    : 30
  const link = `${config.frontendUrl}/reset-password?token=${encodeURIComponent(token)}`
  const greeting = greetingFor(name)

  await sendMail({
    to,
    siteName: site,
    subject: `Reset your ${site} password`,
    text: [
      greeting,
      '',
      `Use the link below to choose a new ${site} password. It expires in ${minutes} minutes.`,
      link,
      '',
      'If you did not request this, you can ignore this email.',
    ].join('\n'),
    html: `
      <p>${escapeHtml(greeting)}</p>
      <p>Use the button below to choose a new ${escapeHtml(site)} password. It expires in ${minutes} minutes.</p>
      <p><a href="${escapeHtml(link)}" style="background:#06a7ea;color:#fff;padding:12px 20px;text-decoration:none;border-radius:3px;display:inline-block">Reset password</a></p>
      <p>If you did not request this, you can ignore this email.</p>
    `,
  })
}

export async function sendVerificationEmail({ to, name, token }) {
  const site = await siteName()
  const minutes = Number.isFinite(config.verifyTokenTtlMinutes)
    ? Math.max(1, config.verifyTokenTtlMinutes)
    : 60
  const link = `${config.frontendUrl}/verify-email?token=${encodeURIComponent(token)}`
  const greeting = greetingFor(name)

  await sendMail({
    to,
    siteName: site,
    subject: `Verify your ${site} email`,
    text: [
      greeting,
      '',
      `Welcome to ${site}! Open the link below to verify your email address, then sign in to your account.`,
      link,
      '',
      `This link expires in ${minutes} minutes. If you did not create this account, you can ignore this email.`,
    ].join('\n'),
    html: `
      <p>${escapeHtml(greeting)}</p>
      <p>Welcome to ${escapeHtml(site)}! Verify your email address before signing in.</p>
      <p><a href="${escapeHtml(link)}" style="background:#06a7ea;color:#fff;padding:12px 20px;text-decoration:none;border-radius:3px;display:inline-block">Verify email</a></p>
      <p>This link expires in ${minutes} minutes. If you did not create this account, you can ignore this email.</p>
    `,
  })
}
