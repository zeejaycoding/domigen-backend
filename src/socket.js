import jwt from 'jsonwebtoken'
import { Server } from 'socket.io'
import { config } from './config.js'

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

  const authorize = (socket, token) => {
    if (!token) return false
    try {
      const payload = jwt.verify(token, config.jwtSecret)
      if (payload.role === 'admin') {
        socket.join('admin')
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

    socket.on('admin:auth', (token) => {
      const ok = authorize(socket, token)
      socket.emit('admin:auth:result', { ok })
    })

    socket.on('member:auth', (token) => {
      const ok = authorize(socket, token)
      socket.emit('member:auth:result', { ok })
    })
  })

  return io
}
