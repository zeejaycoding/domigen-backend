import jwt from 'jsonwebtoken'
import { Server } from 'socket.io'
import { config } from './config.js'
import { collections } from './db.js'
import { findById } from './helpers.js'
import { isActiveAdmin, scopeFromPayload } from './middleware.js'

export function setupRealtime(httpServer) {
  const io = new Server(httpServer, {
    cors: {
      origin: (origin, callback) => {
        if (!origin || config.allowAllOrigins || config.allowedOrigins.includes(origin)) {
          callback(null, true)
        } else {
          callback(new Error(`Origin ${origin} is not allowed by Socket.IO CORS.`))
        }
      },
      credentials: true,
    },
  })

  const authorize = async (socket, token) => {
    if (!token) return false
    try {
      const payload = jwt.verify(token, config.jwtSecret)
      if (payload.role === 'admin') {
        if (payload.sub) {
          const user = await findById(collections.users(), payload.sub)
          if (!user || !isActiveAdmin(user)) return false
          if (Number(payload.ver || 0) !== Number(user.passwordVersion || 0)) return false
        }
        // Product-only admins stay out of the admin room used for payments,
        // users and tickets. Product updates are emitted publicly already.
        socket.join(scopeFromPayload(payload) === 'all' ? 'admin' : 'admin-products')
        return true
      }
      if (payload.role === 'member') {
        socket.join(`member:${payload.sub}`)
        return true
      }
      return false
    } catch {
      return false
    }
  }

  io.on('connection', (socket) => {
    authorize(socket, socket.handshake.auth?.token)

    socket.on('admin:auth', async (token) => {
      const ok = await authorize(socket, token)
      socket.emit('admin:auth:result', { ok })
    })

    socket.on('member:auth', async (token) => {
      const ok = await authorize(socket, token)
      socket.emit('member:auth:result', { ok })
    })
  })

  return io
}
