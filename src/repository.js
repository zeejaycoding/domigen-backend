import { collections } from './db.js'
import { DEFAULT_SETTINGS, publicPayment, publicProduct, publicSettings, publicUser } from './helpers.js'

export async function listProducts() {
  const docs = await collections.products().find({}).sort({ _id: 1 }).toArray()
  return docs.map(publicProduct)
}

export async function listPayments() {
  const docs = await collections.payments().find({}).sort({ date: -1, id: -1 }).toArray()
  return docs.map(publicPayment)
}

export async function listUsers() {
  const docs = await collections.users()
    .find({ status: { $ne: 'Deleted' } })
    .sort({ _id: 1 })
    .toArray()
  return docs.map(publicUser)
}

export async function getSettings() {
  const doc = await collections.settings().findOne({ key: 'site' })
  return publicSettings(doc)
}

export async function publicBootstrap() {
  const [products, settings] = await Promise.all([listProducts(), getSettings()])
  return { products, settings }
}

export async function adminBootstrap() {
  const [products, payments, users, settings] = await Promise.all([
    listProducts(),
    listPayments(),
    listUsers(),
    getSettings(),
  ])
  return { products, payments, users, settings, defaults: DEFAULT_SETTINGS }
}
