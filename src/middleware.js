import jwt from 'jsonwebtoken'
import { config } from './config.js'
import { collections } from './db.js'
import { findById } from './helpers.js'

function readToken(req) {
  const header = req.get('authorization') || ''
  return header.replace(/^Bearer\s+/i, '').trim()
}

export function signAdminToken(email) {
  return jwt.sign({ role: 'admin', email }, config.jwtSecret, { expiresIn: '7d' })
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

export function requireAdmin(req, res, next) {
  const token = readToken(req)
  if (!token) return res.status(401).json({ message: 'Admin sign-in required.' })

  try {
    const payload = jwt.verify(token, config.jwtSecret)
    if (payload.role !== 'admin') return res.status(403).json({ message: 'Admin access required.' })
    req.admin = payload
    return next()
  } catch {
    return res.status(401).json({ message: 'Your admin session expired. Sign in again.' })
  }
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
