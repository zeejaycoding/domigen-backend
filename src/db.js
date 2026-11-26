import { MongoClient } from 'mongodb'
import { config } from './config.js'

let client = null
let db = null

export const collections = {
  products: () => db.collection('products'),
  payments: () => db.collection('payments'),
  users: () => db.collection('users'),
  tickets: () => db.collection('tickets'),
  settings: () => db.collection('site_settings'),
}

export async function connectDatabase() {
  if (db) return db

  client = new MongoClient(config.mongoUri, {
    serverSelectionTimeoutMS: 15000,
    maxPoolSize: 20,
  })

  await client.connect()
  db = client.db(config.dbName)

  await Promise.allSettled([
    collections.products().createIndex({ id: 1 }, { unique: true }),
    collections.payments().createIndex({ id: 1 }, { unique: true }),
    collections.payments().createIndex({ stripeSessionId: 1 }, { unique: true, sparse: true }),
    collections.users().createIndex({ emailLower: 1 }, { unique: true, sparse: true }),
    collections.tickets().createIndex({ memberId: 1 }),
    collections.tickets().createIndex({ email: 1 }),
    collections.settings().createIndex({ key: 1 }, { unique: true }),
  ])

  return db
}

export function getDb() {
  if (!db) throw new Error('Database has not been connected yet.')
  return db
}

export async function closeDatabase() {
  await client?.close()
  client = null
  db = null
}
