import jwt from 'jsonwebtoken'
import { config } from './config.js'
import { collections } from './db.js'
import { findById } from './helpers.js'

function readToken(req) {
  const header = req.get('authorization') || ''
  return header.replace(/^Bearer\s+/i, '').trim()
}

// Only the built-in account has full access. Every database-backed admin —
// regardless of the "Admin" label on their user record — is products-only.
export function adminScope(email) {
  return String(email).trim().toLowerCase() === config.adminEmail.toLowerCase()
    ? 'all'
    : 'products'
}

export function scopeFromPayload(payload) {
  if (payload?.scope === 'all' || payload?.scope === 'products') return payload.scope
  // Tokens issued before scopes existed: a linked user was an added admin, so
  // treat it as products-only; the standalone token was the built-in admin.
  return payload?.sub ? 'products' : 'all'
}

export function isActiveAdmin(user) {
  if (!user) return false
  if (String(user.role || '').toLowerCase() !== 'admin') return false
  if (user.emailVerified === false) return false
  if (user.status && user.status !== 'Active') return false
  return Boolean(user.status) || user.active !== false
}

export function signAdminToken(email, user = null) {
  const payload = { role: 'admin', email, scope: adminScope(email) }
  if (user) {
    // Linking the token to the account lets requireAdmin revoke access when an
    // admin account is suspended, deleted, demoted or given a new password.
    payload.sub = String(user._id)
    payload.ver = Number(user.passwordVersion || 0)
  }
  return jwt.sign(payload, config.jwtSecret, { expiresIn: '7d' })
}

export function signMemberToken(user) {
  return jwt.sign({
    role: 'member',
    sub: String(user._id),
    email: user.email,
    ver: Number(user.passwordVersion || 0),
  }, config.jwtSecret, {
    expiresIn: '30d',
  })
}

export async function requireAdmin(req, res, next) {
  const token = readToken(req)
  if (!token) return res.status(401).json({ message: 'Admin sign-in required.' })

  try {
    const payload = jwt.verify(token, config.jwtSecret)
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Admin access required.' })

    if (payload.sub) {
      const user = await findById(collections.users(), payload.sub)
      if (!user || user.status === 'Deleted') {
        return res.status(401).json({
          code: 'ACCOUNT_DELETED',
          message: 'This admin account has been deleted. Please sign in again.',
        })
      }
      if (!isActiveAdmin(user)) {
        return res.status(403).json({ message: 'Admin access is no longer available for this account.' })
      }
      if (Number(payload.ver || 0) !== Number(user.passwordVersion || 0)) {
        return res.status(401).json({ message: 'Your admin password changed. Please sign in again.' })
      }
      req.adminUser = user
    }

    req.admin = { ...payload, scope: scopeFromPayload(payload) }
    return next()
  } catch {
    return res.status(401).json({ message: 'Your admin session expired. Sign in again.' })
  }
}

export function requireFullAdmin(req, res, next) {
  if (scopeFromPayload(req.admin) !== 'all') {
    return res.status(403).json({ message: 'This account only has access to products.' })
  }
  return next()
}

export async function requireMember(req, res, next) {
  const token = readToken(req)
  if (!token) return res.status(401).json({ message: 'Sign in required.' })

  let payload
  try {
    payload = jwt.verify(token, config.jwtSecret)
  } catch {
    return res.status(401).json({ message: 'Your session expired. Sign in again.' })
  }
  if (payload.role !== 'member') return res.status(403).json({ message: 'Member access required.' })

  try {
    const user = await findById(collections.users(), payload.sub)
    if (!user || user.status === 'Deleted') {
      return res.status(401).json({
        code: 'ACCOUNT_DELETED',
        message: 'This account has been deleted and is no longer available.',
      })
    }
    if (Number(payload.ver || 0) !== Number(user.passwordVersion || 0)) {
      return res.status(401).json({
        code: 'ACCOUNT_PASSWORD_CHANGED',
        message: 'Your password was changed. Please sign in again.',
      })
    }
    if (user.emailVerified === false) {
      return res.status(403).json({
        code: 'EMAIL_NOT_VERIFIED',
        message: 'Please verify your email before continuing.',
      })
    }
    if (user.status === 'Suspended' || (!user.status && user.active === false)) {
      return res.status(403).json({
        code: 'ACCOUNT_SUSPENDED',
        message: 'This account is suspended. Please contact support for help.',
      })
    }

    req.member = payload
    req.memberUser = user
    return next()
  } catch (error) {
    console.error(error)
    return res.status(500).json({ message: 'Something went wrong on the server.' })
  }
}

export function optionalMember(req, _res, next) {
  const token = readToken(req)
  if (token) {
    try {
      req.member = jwt.verify(token, config.jwtSecret)
    } catch {
      /* An expired member token simply means this is a guest checkout. */
    }
  }
  next()
}

export function corsOrigin(origin, callback) {
  if (!origin || config.allowAllOrigins || config.allowedOrigins.includes(origin)) {
    return callback(null, true)
  }
  return callback(new Error(`Origin ${origin} is not allowed by CORS.`))
}

export function errorHandler(error, _req, res, _next) {
  if (error?.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ message: 'The uploaded file is too large.' })
  }
  if (error?.message?.startsWith('Origin ')) {
    return res.status(403).json({ message: error.message })
  }
  if (error?.code === 11000) {
    return res.status(409).json({ message: 'That email is already registered.' })
  }
  console.error(error)
  return res.status(500).json({ message: 'Something went wrong on the server.' })
}
