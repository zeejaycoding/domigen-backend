import bcrypt from 'bcryptjs'
import { Router } from 'express'
import { config } from './config.js'
import { getDb, collections } from './db.js'
import {
  asyncRoute,
  findById,
  isEmail,
  nextOrderId,
  nextNumericId,
  normalizeProductInput,
  publicPayment,
  publicProduct,
  publicUser,
  sanitizeSettings,
} from './helpers.js'
import {
  requireAdmin,
  requireMember,
  signAdminToken,
  signMemberToken,
} from './middleware.js'
import {
  createCheckoutSession,
  paymentPublicConfig,
  recordPaidSession,
  retrieveCheckoutSession,
} from './stripe.js'
import {
  adminBootstrap,
  getSettings,
  listPayments,
  listProducts,
  listUsers,
  publicBootstrap,
} from './repository.js'

const router = Router()

async function emitProducts(req) {
  req.app.get('io')?.emit('products', await listProducts())
}

async function emitPayments(req) {
  req.app.get('io')?.to('admin').emit('payments', await listPayments())
}

async function emitUsers(req) {
  req.app.get('io')?.to('admin').emit('users', await listUsers())
}

async function emitSettings(req) {
  req.app.get('io')?.emit('settings', await getSettings())
}

function findProductByKey(key) {
  const clauses = [{ slug: String(key) }, { id: String(key) }]
  const numeric = Number(key)
  if (Number.isFinite(numeric)) clauses.push({ id: numeric })
  return collections.products().findOne({ $or: clauses })
}

async function findAccountByEmail(email, statusFilter = { status: { $ne: 'Deleted' } }) {
  const lower = String(email).trim().toLowerCase()
  return collections.users().findOne({
    ...statusFilter,
    $or: [{ emailLower: lower }, { email: { $regex: `^${lower.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, $options: 'i' } }],
  })
}

function findDeletedAccountByEmail(email) {
  return findAccountByEmail(email, { status: 'Deleted' })
}

function notifyMember(req, userId, event, message) {
  req.app.get('io')?.to(`member:${String(userId)}`).emit(event, { message })
}

// ---------------------------------------------------------------------------
// Health / bootstrap
// ---------------------------------------------------------------------------

router.get('/health', asyncRoute(async (_req, res) => {
  await getDb().command({ ping: 1 })
  res.json({ ok: true, database: 'connected', time: new Date().toISOString() })
}))

router.get('/bootstrap', asyncRoute(async (_req, res) => {
  res.json(await publicBootstrap())
}))

router.get('/admin/bootstrap', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await adminBootstrap())
}))

// ---------------------------------------------------------------------------
// Public catalogue
// ---------------------------------------------------------------------------

router.get('/products', asyncRoute(async (_req, res) => {
  res.json(await listProducts())
}))

router.get('/products/:key', asyncRoute(async (req, res) => {
  const doc = await findProductByKey(req.params.key)
  if (!doc) return res.status(404).json({ message: 'Product not found.' })
  return res.json(publicProduct(doc))
}))

router.post('/products', requireAdmin, asyncRoute(async (req, res) => {
  const title = String(req.body?.title || '').trim()
  if (title.length < 3) return res.status(400).json({ message: 'Product title needs at least 3 characters.' })
  if (Number(req.body?.price) < 0) return res.status(400).json({ message: 'Enter a valid price.' })

  const id = await nextNumericId(collections.products())
  const product = normalizeProductInput(req.body, { id })
  await collections.products().insertOne(product)
  await emitProducts(req)
  return res.status(201).json(publicProduct(product))
}))

router.put('/products/:id', requireAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.products(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Product not found.' })

  const product = normalizeProductInput(req.body, existing)
  if (product.title.length < 3) return res.status(400).json({ message: 'Product title needs at least 3 characters.' })
  await collections.products().updateOne({ _id: existing._id }, { $set: product })
  await emitProducts(req)
  return res.json(publicProduct({ ...existing, ...product }))
}))

router.delete('/products/:id', requireAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.products(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Product not found.' })
  await collections.products().deleteOne({ _id: existing._id })
  await emitProducts(req)
  return res.json({ ok: true })
}))

// ---------------------------------------------------------------------------
// Site settings
// ---------------------------------------------------------------------------

router.get('/settings', asyncRoute(async (_req, res) => {
  res.json(await getSettings())
}))

router.put('/settings', requireAdmin, asyncRoute(async (req, res) => {
  const settings = sanitizeSettings(req.body)
  if (settings.name.length < 2) return res.status(400).json({ message: 'Website name needs at least 2 characters.' })
  await collections.settings().updateOne(
    { key: 'site' },
    { $set: { ...settings, key: 'site', updatedAt: new Date() } },
    { upsert: true },
  )
  await emitSettings(req)
  return res.json(settings)
}))

// ---------------------------------------------------------------------------
// Public members (the existing `users` collection — no extra user tables)
// ---------------------------------------------------------------------------

router.post('/auth/signup', asyncRoute(async (req, res) => {
  const username = String(req.body?.username || req.body?.name || '').trim()
  const email = String(req.body?.email || '').trim()
  const password = String(req.body?.password || '')

  if (username.length < 3) return res.status(400).json({ message: 'Username needs at least 3 characters.' })
  if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' })
  if (password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' })
  if (await findAccountByEmail(email)) {
    return res.status(409).json({ message: 'That email is already registered.' })
  }

  const id = await nextNumericId(collections.users())
  const passwordHash = await bcrypt.hash(password, 10)
  const doc = {
    id,
    name: username,
    username,
    email,
    emailLower: email.toLowerCase(),
    passwordHash,
    role: 'Member',
    status: 'Active',
    joined: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
  }

  await collections.users().insertOne(doc)
  await emitUsers(req)
  return res.status(201).json({ token: signMemberToken(doc), user: publicUser(doc) })
}))

router.post('/auth/signin', asyncRoute(async (req, res) => {
  const email = String(req.body?.email || '').trim()
  const password = String(req.body?.password || '')
  if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' })
  if (!password) return res.status(400).json({ message: 'Enter your password.' })

  const doc = await findAccountByEmail(email)
  if (!doc) {
    if (await findDeletedAccountByEmail(email)) {
      return res.status(410).json({
        code: 'ACCOUNT_DELETED',
        message: 'This account has been deleted and is no longer available.',
      })
    }
    return res.status(401).json({ message: 'Invalid email or password.' })
  }

  let valid = false
  if (doc.passwordHash) valid = await bcrypt.compare(password, doc.passwordHash)
  if (!valid && typeof doc.password === 'string') valid = doc.password === password

  if (!valid) return res.status(401).json({ message: 'Invalid email or password.' })
  if (doc.status === 'Suspended' || (!doc.status && doc.active === false)) {
    return res.status(403).json({
      code: 'ACCOUNT_SUSPENDED',
      message: 'This account is suspended. Please contact support for help.',
    })
  }

  return res.json({ token: signMemberToken(doc), user: publicUser(doc) })
}))

router.get('/auth/me', requireMember, asyncRoute(async (req, res) => {
  const doc = await findById(collections.users(), req.member.sub)
  if (!doc) return res.status(404).json({ message: 'Account not found.' })
  res.json(publicUser(doc))
}))

// ---------------------------------------------------------------------------
// Stripe checkout (card + Apple Pay)
// ---------------------------------------------------------------------------

router.get('/payments/config', (_req, res) => {
  res.json(paymentPublicConfig())
})

router.get('/checkout/session/:id', requireMember, asyncRoute(async (req, res) => {
  const session = await retrieveCheckoutSession(req.params.id)
  if (session.metadata?.memberId && String(session.metadata.memberId) !== String(req.member.sub)) {
    return res.status(403).json({ message: 'You cannot view this order.' })
  }

  // Trusted fallback if the webhook has not arrived yet.
  if (session.payment_status === 'paid') await recordPaidSession(session, req)

  return res.json({
    paid: session.payment_status === 'paid',
    product: String(session.metadata?.productTitle || 'DOMIGEN product'),
    amount: Number(session.amount_total || 0) / 100,
  })
}))

router.post('/checkout/session', requireMember, asyncRoute(async (req, res) => {
  const product = await findById(collections.products(), req.body?.productId)
  if (!product) return res.status(404).json({ message: 'Product not found.' })

  const safeProduct = publicProduct(product)
  const free = String(safeProduct.badge || '').toLowerCase() === 'free'
    || Number(safeProduct.price) === 0

  if (free) return res.json({ free: true })

  const session = await createCheckoutSession({
    product: safeProduct,
    member: req.member,
    wallet: req.body?.wallet === 'applepay' ? 'applepay' : 'card',
    req,
  })
  return res.json({ free: false, ...session })
}))

// ---------------------------------------------------------------------------
// Free orders only — paid orders are created by the Stripe webhook
// ---------------------------------------------------------------------------

router.post('/payments', requireMember, asyncRoute(async (req, res) => {
  const productId = req.body?.productId
  const product = productId ? await findById(collections.products(), productId) : null
  const free = String(product?.badge || '').toLowerCase() === 'free' || Number(product?.price) === 0
  if (!free) {
    return res.status(400).json({ message: 'Use Stripe checkout for paid products.' })
  }

  const method = 'Free'
  const title = String(req.body?.product || product?.title || 'DOMIGEN product').trim().slice(0, 120)
  const amount = free ? 0 : Number(req.body?.amount ?? product?.price ?? 0)
  const customer = String(
    req.body?.customer || req.member?.email || '',
  ).trim().slice(0, 80) || 'Member'

  if (!Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ message: 'Invalid payment amount.' })
  }

  const doc = {
    id: await nextOrderId(),
    customer,
    product: title,
    amount,
    method,
    status: free ? 'Completed' : 'Pending',
    date: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
    ...(method === 'Card' && /^\d{4}$/.test(String(req.body?.last4 || ''))
      ? { last4: String(req.body.last4) }
      : {}),
  }

  await collections.payments().insertOne(doc)

  if (product?._id) {
    await collections.products().updateOne({ _id: product._id }, { $inc: { sold: 1 } })
    await emitProducts(req)
  }

  await emitPayments(req)
  return res.status(201).json(publicPayment(doc))
}))

// ---------------------------------------------------------------------------
// Admin auth / users / payments
// ---------------------------------------------------------------------------

router.post('/admin/login', (req, res) => {
  const email = String(req.body?.email || '').trim()
  const password = String(req.body?.password || '')

  if (email !== config.adminEmail || password !== config.adminPassword) {
    return res.status(401).json({ message: 'Invalid email or password.' })
  }

  return res.json({ token: signAdminToken(email), admin: { email } })
})

router.get('/admin/payments', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await listPayments())
}))

router.post('/admin/payments', requireAdmin, asyncRoute(async (req, res) => {
  const customer = String(req.body?.customer || '').trim().slice(0, 80) || 'Manual entry'
  const product = String(req.body?.product || '').trim().slice(0, 120) || 'DOMIGEN product'
  const amount = Number(req.body?.amount ?? 0)
  const method = ['Card', 'Apple Pay', 'Free', 'Manual'].includes(req.body?.method)
    ? req.body.method
    : 'Manual'
  const status = ['Completed', 'Pending', 'Delayed', 'Refunded'].includes(req.body?.status)
    ? req.body.status
    : 'Pending'

  if (!Number.isFinite(amount) || amount < 0) {
    return res.status(400).json({ message: 'Enter a valid amount.' })
  }

  const doc = {
    id: await nextOrderId(),
    customer,
    product,
    amount,
    method,
    status,
    date: String(req.body?.date || new Date().toISOString().slice(0, 10)).slice(0, 10),
    createdAt: new Date(),
  }
  await collections.payments().insertOne(doc)
  await emitPayments(req)
  return res.status(201).json(publicPayment(doc))
}))

router.patch('/admin/payments/:id', requireAdmin, asyncRoute(async (req, res) => {
  const status = String(req.body?.status || '')
  if (!['Completed', 'Pending', 'Delayed', 'Refunded'].includes(status)) {
    return res.status(400).json({ message: 'Invalid payment status.' })
  }
  const existing = await findById(collections.payments(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Payment not found.' })

  await collections.payments().updateOne({ _id: existing._id }, { $set: { status } })
  await emitPayments(req)
  return res.json(publicPayment({ ...existing, status }))
}))

router.delete('/admin/payments/:id', requireAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.payments(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Payment not found.' })
  await collections.payments().deleteOne({ _id: existing._id })
  await emitPayments(req)
  return res.json({ ok: true })
}))

router.get('/admin/users', requireAdmin, asyncRoute(async (_req, res) => {
  res.json(await listUsers())
}))

router.post('/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const name = String(req.body?.name || '').trim()
  const email = String(req.body?.email || '').trim()
  const password = String(req.body?.password || '')
  const role = ['Member', 'Admin'].includes(req.body?.role) ? req.body.role : 'Member'

  if (name.length < 2) return res.status(400).json({ message: 'Enter a name with at least 2 characters.' })
  if (!isEmail(email)) return res.status(400).json({ message: 'Enter a valid email address.' })
  if (password.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' })
  if (await findAccountByEmail(email)) {
    return res.status(409).json({ message: 'That email is already registered.' })
  }

  const id = await nextNumericId(collections.users())
  const doc = {
    id,
    name,
    username: name,
    email,
    emailLower: email.toLowerCase(),
    password,
    passwordHash: await bcrypt.hash(password, 10),
    role,
    status: 'Active',
    joined: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
  }
  await collections.users().insertOne(doc)
  await emitUsers(req)
  return res.status(201).json(publicUser(doc))
}))

router.patch('/admin/users/:id', requireAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.users(), req.params.id)
  if (!existing || existing.status === 'Deleted') {
    return res.status(404).json({ message: 'User not found.' })
  }

  const patch = {}
  if (req.body?.name !== undefined) patch.name = String(req.body.name).trim()
  if (req.body?.password !== undefined && String(req.body.password) !== '') {
    const password = String(req.body.password)
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters.' })
    }
    patch.password = password
    patch.passwordHash = await bcrypt.hash(password, 10)
  }
  if (req.body?.role !== undefined && ['Member', 'Admin'].includes(req.body.role)) patch.role = req.body.role
  if (req.body?.status !== undefined && ['Active', 'Suspended'].includes(req.body.status)) {
    patch.status = req.body.status
    patch.active = req.body.status === 'Active'
  }
  if (req.body?.email !== undefined) {
    const email = String(req.body.email).trim()
    if (!isEmail(email)) return res.status(400).json({ message: 'Enter a valid email address.' })
    const duplicate = await findAccountByEmail(email)
    if (duplicate && String(duplicate._id) !== String(existing._id)) {
      return res.status(409).json({ message: 'That email is already registered.' })
    }
    patch.email = email
    patch.emailLower = email.toLowerCase()
  }

  await collections.users().updateOne({ _id: existing._id }, { $set: patch })
  await emitUsers(req)

  if (patch.passwordHash) {
    notifyMember(
      req,
      existing._id,
      'account:password-changed',
      'Your password was changed by an administrator. Please sign in again.',
    )
  }

  if (patch.status === 'Suspended' && existing.status !== 'Suspended') {
    notifyMember(
      req,
      existing._id,
      'account:suspended',
      'Your account has been suspended. Please contact support for help.',
    )
  }

  return res.json(publicUser({ ...existing, ...patch }))
}))

router.delete('/admin/users/:id', requireAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.users(), req.params.id)
  if (!existing || existing.status === 'Deleted') {
    return res.status(404).json({ message: 'User not found.' })
  }

  // A soft delete keeps the account unavailable for sign-in (with a clear
  // message) without adding another collection or reusing the email silently.
  await collections.users().updateOne(
    { _id: existing._id },
    { $set: { status: 'Deleted', active: false, deletedAt: new Date() } },
  )
  await emitUsers(req)
  notifyMember(
    req,
    existing._id,
    'account:deleted',
    'Your account has been deleted and is no longer available.',
  )
  return res.json({ ok: true })
}))

export default router
