import { ObjectId } from 'mongodb'
import { collections } from './db.js'

export const DEFAULT_SETTINGS = {
  name: 'DOMIGEN',
  tagline: 'Gaming . accounts . tools',
  logo: '/images/domigen-logo.jpeg',
}

export function isEmail(value) {
  return /^\S+@\S+\.\S+$/.test(String(value || '').trim())
}

export function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

function asNumber(value, fallback) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

export function publicId(doc) {
  if (doc?.id !== undefined && doc.id !== null && doc.id !== '') {
    const numeric = asNumber(doc.id, null)
    return numeric === null ? String(doc.id) : numeric
  }
  return doc?._id ? String(doc._id) : ''
}

async function toObjectId(value) {
  try {
    return ObjectId.isValid(value) ? new ObjectId(value) : null
  } catch {
    return null
  }
}

export async function findById(collection, id) {
  const objectId = await toObjectId(id)
  const clauses = [{ id: String(id) }, { id: asNumber(id, null) }]
  if (objectId) clauses.push({ _id: objectId })
  return collection.findOne({ $or: clauses })
}

export async function nextNumericId(collection) {
  const docs = await collection.find({}, { projection: { id: 1 } }).toArray()
  return docs.reduce((max, doc) => Math.max(max, asNumber(doc.id, 0)), 0) + 1
}

export async function nextOrderId() {
  const docs = await collections.payments()
    .find({}, { projection: { id: 1 } })
    .toArray()
  const highest = docs.reduce((max, doc) => {
    const match = String(doc.id || '').match(/\d+$/)
    return Math.max(max, match ? Number(match[0]) : 0)
  }, 1041)
  return `NG-${highest + 1}`
}

export function publicProduct(doc) {
  if (!doc) return null
  const { _id, passwordHash, ...rest } = doc
  const product = { ...rest }
  product.id = publicId(doc)
  product.images = Array.isArray(product.images) ? product.images.filter(Boolean) : []
  if (!product.images.length && product.image) product.images = [product.image]
  product.features = Array.isArray(product.features) ? product.features.filter(Boolean) : []
  product.video = typeof product.video === 'string' ? product.video : ''
  product.published = product.published || new Date().toISOString().slice(0, 10)
  product.publishedAt = product.publishedAt || `${product.published} 00:00:00`
  product.badge = product.badge || ''
  if (String(product.badge).toLowerCase() === 'free') product.price = 0
  product.contact = product.contact || 'DOMIGEN Team'
  product.version = product.version || '1.0'
  product.sold = Math.max(0, asNumber(product.sold, 0))
  product.featured = Boolean(
    product.featured || ['Featured', 'Bestseller'].includes(product.badge),
  )
  product.latest = Boolean(product.latest || product.badge === 'New')
  product.slug = product.slug || `${product.id}-${slugify(product.title)}`
  return product
}

export function normalizeProductInput(body = {}, existing = {}) {
  const title = String(body.title ?? existing.title ?? '').trim()
  const id = publicId(existing) || asNumber(body.id, 0)
  const published = String(body.published ?? existing.published ?? new Date().toISOString().slice(0, 10))
  const providedSlug = String(body.slug ?? '').trim()
  const slug = providedSlug || `${id}-${slugify(title)}`
  const badge = String(body.badge ?? existing.badge ?? '').trim()
  const price = badge.toLowerCase() === 'free'
    ? 0
    : Math.max(0, asNumber(body.price ?? existing.price ?? 0, 0))

  const product = {
    id: asNumber(id, String(existing._id || '')),
    slug,
    title,
    game: String(body.game ?? existing.game ?? 'MW3').trim(),
    category: String(body.category ?? existing.category ?? 'Mod').trim(),
    price,
    badge,
    contact: String(body.contact ?? existing.contact ?? 'DOMIGEN Team').trim() || 'DOMIGEN Team',
    published,
    publishedAt: String(
      body.publishedAt ??
        existing.publishedAt ??
        `${published} ${new Date().toISOString().slice(11, 19)}`,
    ),
    version: String(body.version ?? existing.version ?? '1.0').trim() || '1.0',
    description: String(body.description ?? existing.description ?? '').trim(),
    image: typeof body.image === 'string' ? body.image : existing.image || '',
    images: Array.isArray(body.images)
      ? body.images.filter((item) => typeof item === 'string' && item)
      : existing.images || [],
    video: typeof body.video === 'string' ? body.video.trim() : existing.video || '',
    features: Array.isArray(body.features)
      ? body.features.filter((item) => typeof item === 'string' && item)
      : existing.features || [],
    // Sales count is managed by checkout, never by the product form.
    sold: Math.max(0, asNumber(existing.sold, 0)),
  }

  product.featured = Boolean(
    body.featured ?? existing.featured ?? ['Featured', 'Bestseller'].includes(product.badge),
  )
  product.latest = Boolean(body.latest ?? existing.latest ?? product.badge === 'New')

  if (!product.images.length && product.image) product.images = [product.image]
  return product
}

export function publicPayment(doc) {
  if (!doc) return null
  const { _id, ...rest } = doc
  const payment = { ...rest }
  payment.id = payment.id || String(_id)
  payment.amount = asNumber(payment.amount, 0)
  payment.status = payment.status || ''
  payment.date = payment.date || new Date().toISOString().slice(0, 10)
  // Card details are copied only from the Stripe-backed fields.
  payment.cardBrand = payment.stripeCardBrand || ''
  payment.cardLast4 = payment.stripeCardLast4 || ''
  return payment
}

export function publicUser(doc) {
  if (!doc) return null
  const { _id, passwordHash, password, passwordVersion, resetTokenHash, resetTokenExpires, ...rest } = doc
  const user = { ...rest }
  user.id = publicId(doc)
  user.name = user.name || user.username || String(user.email || 'Member').split('@')[0]
  user.email = user.email || ''
  user.role = user.role || 'Member'
  user.status = user.status || (user.active === false ? 'Suspended' : 'Active')
  user.joined = user.joined || String(user.createdAt || new Date().toISOString()).slice(0, 10)
  return user
}

export function publicSettings(doc) {
  return {
    ...DEFAULT_SETTINGS,
    name: String(doc?.name ?? DEFAULT_SETTINGS.name).slice(0, 60),
    tagline: String(doc?.tagline ?? DEFAULT_SETTINGS.tagline).slice(0, 80),
    logo: typeof doc?.logo === 'string' && doc.logo ? doc.logo : DEFAULT_SETTINGS.logo,
  }
}

export function sanitizeSettings(body = {}) {
  return {
    name: String(body.name ?? DEFAULT_SETTINGS.name).trim().slice(0, 60) || DEFAULT_SETTINGS.name,
    tagline: String(body.tagline ?? DEFAULT_SETTINGS.tagline).trim().slice(0, 80) || DEFAULT_SETTINGS.tagline,
    logo: typeof body.logo === 'string' && body.logo ? body.logo : DEFAULT_SETTINGS.logo,
  }
}

export function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next)
}
