import bcrypt from 'bcryptjs'
import crypto from 'node:crypto'
import { Router } from 'express'
import { config } from './config.js'
import {
  emailConfigured,
  sendPasswordResetEmail,
  sendVerificationEmail,
} from './mailer.js'
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
  publicTicket,
  publicUser,
  sanitizeSettings,
} from './helpers.js'
import {
  adminScope,
  isActiveAdmin,
  requireAdmin,
  requireFullAdmin,
  requireMember,
  scopeFromPayload,
  signAdminToken,
  signMemberToken,
} from './middleware.js'
import {
  createCheckoutSession,
  paymentsEnabled,
  paymentPublicConfig,
  recordStripeSession,
  retrieveCheckoutSession,
  syncStripePayments,
} from './stripe.js'
import {
  adminBootstrap,
  getSettings,
  listPayments,
  listProducts,
  listTickets,
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

async function freshAdminPayments(req) {
  const sync = paymentsEnabled()
    ? await syncStripePayments(req)
    : {
      stripeConfigured: false,
      checked: 0,
      paid: 0,
      updated: 0,
      removed: 0,
      syncedAt: new Date().toISOString(),
    }

  return { payments: await listPayments(), sync }
}

async function emitUsers(req) {
  req.app.get('io')?.to('admin').emit('users', await listUsers())
}

async function emitTickets(req) {
  req.app.get('io')?.to('admin').emit('tickets', await listTickets())
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

function exactTextMatch(value) {
  return new RegExp(`^${String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i')
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

function emitToMember(req, userId, event, payload) {
  req.app.get('io')?.to(`member:${String(userId)}`).emit(event, payload)
}

function notifyMember(req, userId, event, message) {
  emitToMember(req, userId, event, { message })
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex')
}

// Verification links use the same hashed-token pattern as password resets:
// only the hash is stored, and the token is removed once it has been used.
function verificationTokenExpiry() {
  const minutes = Number.isFinite(config.verifyTokenTtlMinutes)
    ? Math.max(1, config.verifyTokenTtlMinutes)
    : 60
  return new Date(Date.now() + minutes * 60 * 1000)
}

function verificationPatch() {
  const token = crypto.randomBytes(32).toString('hex')
  return {
    token,
    patch: {
      emailVerified: false,
      emailVerifyTokenHash: hashResetToken(token),
      emailVerifyExpires: verificationTokenExpiry(),
      emailVerifySentAt: new Date(),
    },
  }
}

async function passwordMatches(doc, password) {
  if (doc?.passwordHash && await bcrypt.compare(password, doc.passwordHash)) return true
  return typeof doc?.password === 'string' && doc.password === password
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

router.get('/admin/bootstrap', requireAdmin, asyncRoute(async (req, res) => {
  // Product-only admins never receive payments, users, tickets or a Stripe sync.
  if (scopeFromPayload(req.admin) === 'products') {
    const [products, settings] = await Promise.all([listProducts(), getSettings()])
    return res.json({ products, settings, paymentSync: null })
  }

  const data = await adminBootstrap()
  const fresh = await freshAdminPayments(req)
  res.json({ ...data, payments: fresh.payments, paymentSync: fresh.sync })
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

router.put('/settings', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
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
  if (!emailConfigured()) {
    return res.status(503).json({
      message: 'Email verification is not configured yet. Please contact support.',
    })
  }

  const id = await nextNumericId(collections.users())
  const passwordHash = await bcrypt.hash(password, 10)
  const { token, patch } = verificationPatch()
  const doc = {
    id,
    name: username,
    username,
    email,
    emailLower: email.toLowerCase(),
    passwordHash,
    passwordVersion: 0,
    role: 'Member',
    status: 'Active',
    joined: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
    ...patch,
  }

  const result = await collections.users().insertOne(doc)
  try {
    await sendVerificationEmail({ to: email, name: username, token })
  } catch (error) {
    console.error('Verification email failed:', error)
    // Remove the unfinished account so the member can correct the address and retry.
    await collections.users().deleteOne({ _id: result.insertedId, emailVerified: false })
    return res.status(502).json({
      message: "We couldn't send the verification email. Please check the address and try again.",
    })
  }

  await emitUsers(req)
  // No token is returned: the account cannot be used until the link is opened.
  return res.status(201).json({
    message: 'Check your email for a verification link before signing in.',
    email,
    requiresVerification: true,
  })
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

  if (!(await passwordMatches(doc, password))) {
    return res.status(401).json({ message: 'Invalid email or password.' })
  }
  // Accounts created before verification existed (or added by an admin) stay
  // usable: only an explicit emailVerified: false blocks sign-in.
  if (doc.emailVerified === false) {
    return res.status(403).json({
      code: 'EMAIL_NOT_VERIFIED',
      message: 'Please verify your email before signing in. Check your inbox for the link.',
      email: doc.email,
    })
  }
  if (doc.status === 'Suspended' || (!doc.status && doc.active === false)) {
    return res.status(403).json({
      code: 'ACCOUNT_SUSPENDED',
      message: 'This account is suspended. Please contact support for help.',
    })
  }

  return res.json({ token: signMemberToken(doc), user: publicUser(doc) })
}))

router.post('/auth/verify-email', asyncRoute(async (req, res) => {
  const token = String(req.body?.token || '').trim()
  if (!token) return res.status(400).json({ message: 'This verification link is missing its token.' })

  const doc = await collections.users().findOne({
    emailVerifyTokenHash: hashResetToken(token),
    emailVerifyExpires: { $gt: new Date() },
    status: { $ne: 'Deleted' },
  })
  if (!doc) {
    return res.status(400).json({
      code: 'INVALID_VERIFICATION_TOKEN',
      message: 'This verification link is invalid or has expired. Request a new one from the sign-in page.',
    })
  }

  await collections.users().updateOne(
    { _id: doc._id },
    {
      $set: { emailVerified: true, verifiedAt: new Date() },
      $unset: {
        emailVerifyTokenHash: '',
        emailVerifyExpires: '',
        emailVerifySentAt: '',
      },
    },
  )
  await emitUsers(req)

  return res.json({
    message: 'Email verified. You can sign in now.',
    verified: true,
    email: doc.email,
  })
}))

router.post('/auth/resend-verification', asyncRoute(async (req, res) => {
  const email = String(req.body?.email || '').trim()
  const generic = { message: 'If that account still needs verification, a new link has been sent.' }

  if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' })
  if (!emailConfigured()) {
    return res.status(503).json({ message: 'Email verification is not configured yet. Please contact support.' })
  }

  const doc = await findAccountByEmail(email)
  if (!doc || doc.emailVerified !== false) return res.json(generic)

  const lastSent = doc.emailVerifySentAt ? new Date(doc.emailVerifySentAt).getTime() : 0
  if (Date.now() - lastSent < 60 * 1000) {
    return res.status(429).json({ message: 'Please wait a minute before requesting another link.' })
  }

  const { token, patch } = verificationPatch()
  await collections.users().updateOne({ _id: doc._id }, { $set: patch })

  try {
    await sendVerificationEmail({ to: doc.email, name: doc.name || doc.username, token })
  } catch (error) {
    console.error('Verification email failed:', error)
    return res.status(502).json({ message: "We couldn't send the verification email. Please try again later." })
  }

  return res.json(generic)
}))

router.get('/auth/me', requireMember, asyncRoute(async (req, res) => {
  const doc = await findById(collections.users(), req.member.sub)
  if (!doc) return res.status(404).json({ message: 'Account not found.' })
  res.json(publicUser(doc))
}))

// Account tab: members own their username and email. Changing the email also
// refreshes the token so the email claim stays truthful.
router.put('/auth/account', requireMember, asyncRoute(async (req, res) => {
  const username = String(req.body?.username ?? req.body?.name ?? '').trim()
  const email = String(req.body?.email ?? '').trim()

  if (username.length < 3) return res.status(400).json({ message: 'Username needs at least 3 characters.' })
  if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' })

  const duplicate = await findAccountByEmail(email)
  if (duplicate && String(duplicate._id) !== String(req.memberUser._id)) {
    return res.status(409).json({ message: 'That email is already registered.' })
  }

  const patch = {
    name: username,
    username,
    email,
    emailLower: email.toLowerCase(),
  }
  await collections.users().updateOne({ _id: req.memberUser._id }, { $set: patch })
  await emitUsers(req)

  const updated = { ...req.memberUser, ...patch }
  return res.json({ token: signMemberToken(updated), user: publicUser(updated) })
}))

// My Applications and My Tickets in the signed-in user panel.
router.get('/member/applications', requireMember, asyncRoute(async (req, res) => {
  const clauses = [{ memberId: String(req.member.sub) }]
  const email = String(req.memberUser.email || '').trim()
  if (email) clauses.push({ customer: exactTextMatch(email) })

  const docs = await collections.payments()
    .find({ $or: clauses })
    .sort({ createdAt: -1 })
    .limit(100)
    .toArray()

  return res.json(docs.map(publicPayment))
}))

router.get('/member/tickets', requireMember, asyncRoute(async (req, res) => {
  const clauses = [{ memberId: String(req.member.sub) }]
  const email = String(req.memberUser.email || '').trim()
  if (email) clauses.push({ email: exactTextMatch(email) })

  const docs = await collections.tickets()
    .find({ $or: clauses })
    .sort({ createdAt: -1 })
    .limit(100)
    .toArray()

  return res.json(docs.map(publicTicket))
}))

router.post('/member/tickets', requireMember, asyncRoute(async (req, res) => {
  const subject = String(req.body?.subject || '').trim()
  const message = String(req.body?.message || '').trim()
  if (subject.length < 3) return res.status(400).json({ message: 'Enter a subject with at least 3 characters.' })
  if (message.length < 10) return res.status(400).json({ message: 'Describe your issue in at least 10 characters.' })

  const cleanSubject = subject.slice(0, 120)
  const cleanMessage = message.slice(0, 4000)
  const recentDuplicate = await collections.tickets().findOne({
    memberId: String(req.member.sub),
    subject: cleanSubject,
    message: cleanMessage,
    createdAt: { $gte: new Date(Date.now() - 60 * 1000) },
  })
  if (recentDuplicate) {
    return res.status(409).json({
      message: 'This ticket was just submitted. Please wait a minute before sending it again.',
    })
  }

  const doc = {
    memberId: String(req.member.sub),
    name: String(req.memberUser.name || req.memberUser.username || '').trim(),
    email: String(req.memberUser.email || '').trim(),
    subject: cleanSubject,
    message: cleanMessage,
    status: 'Open',
    response: '',
    date: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
  }

  await collections.tickets().insertOne(doc)
  await emitTickets(req)
  return res.status(201).json(publicTicket(doc))
}))

router.post('/auth/change-password', requireMember, asyncRoute(async (req, res) => {
  const currentPassword = String(req.body?.currentPassword || '')
  const newPassword = String(req.body?.newPassword || '')

  if (!currentPassword) return res.status(400).json({ message: 'Enter your current password.' })
  if (newPassword.length < 8) return res.status(400).json({ message: 'New password must be at least 8 characters.' })

  const doc = req.memberUser
  if (!(await passwordMatches(doc, currentPassword))) {
    return res.status(400).json({ message: 'Your current password is incorrect.' })
  }

  const passwordVersion = Number(doc.passwordVersion || 0) + 1
  await collections.users().updateOne(
    { _id: doc._id },
    {
      $set: {
        passwordHash: await bcrypt.hash(newPassword, 10),
        passwordVersion,
      },
      $unset: { password: '' },
    },
  )
  await emitUsers(req)

  const updated = { ...doc, passwordHash: undefined, password: undefined, passwordVersion }
  return res.json({ token: signMemberToken(updated), user: publicUser(updated) })
}))

router.post('/auth/forgot-password', asyncRoute(async (req, res) => {
  const email = String(req.body?.email || '').trim()
  const generic = { message: 'If an account exists for that email, a reset link has been sent.' }

  if (!isEmail(email)) return res.status(400).json({ message: 'Please enter a valid email address.' })
  if (!emailConfigured()) {
    return res.status(503).json({ message: 'Password reset email is not configured yet. Please contact support.' })
  }

  const doc = await findAccountByEmail(email)
  if (doc) {
    const token = crypto.randomBytes(32).toString('hex')
    const minutes = Number.isFinite(config.resetTokenTtlMinutes)
      ? Math.max(1, config.resetTokenTtlMinutes)
      : 30

    await collections.users().updateOne(
      { _id: doc._id },
      {
        $set: {
          resetTokenHash: hashResetToken(token),
          resetTokenExpires: new Date(Date.now() + minutes * 60 * 1000),
        },
      },
    )

    try {
      await sendPasswordResetEmail({ to: doc.email, name: doc.name || doc.username, token })
    } catch (error) {
      console.error('Password reset email failed:', error)
      return res.status(502).json({ message: 'We could not send the reset email. Please try again later.' })
    }
  }

  return res.json(generic)
}))

router.post('/auth/reset-password', asyncRoute(async (req, res) => {
  const token = String(req.body?.token || '').trim()
  const newPassword = String(req.body?.newPassword || '')

  if (!token) return res.status(400).json({ message: 'This reset link is missing its token.' })
  if (newPassword.length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' })

  const doc = await collections.users().findOne({
    resetTokenHash: hashResetToken(token),
    resetTokenExpires: { $gt: new Date() },
    status: { $ne: 'Deleted' },
  })
  if (!doc) return res.status(400).json({ message: 'This reset link is invalid or has expired.' })

  const passwordVersion = Number(doc.passwordVersion || 0) + 1
  await collections.users().updateOne(
    { _id: doc._id },
    {
      $set: {
        passwordHash: await bcrypt.hash(newPassword, 10),
        passwordVersion,
      },
      $unset: {
        password: '',
        resetTokenHash: '',
        resetTokenExpires: '',
      },
    },
  )
  await emitUsers(req)
  notifyMember(
    req,
    doc._id,
    'account:password-changed',
    'Your password was reset. Please sign in again.',
  )

  return res.json({ message: 'Password updated. You can sign in now.' })
}))

// ---------------------------------------------------------------------------
// Stripe checkout (card + Apple Pay)
// ---------------------------------------------------------------------------

router.get('/payments/config', (_req, res) => {
  res.json(paymentPublicConfig())
})

// Admin re-reads Stripe on demand. Every paid row in the payments collection
// is a mirror of a real Checkout Session; nothing is entered by hand.
router.post('/admin/payments/sync', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
  const fresh = await freshAdminPayments(req)
  res.json({ ...fresh.sync, payments: fresh.payments })
}))

router.get('/checkout/session/:id', requireMember, asyncRoute(async (req, res) => {
  const session = await retrieveCheckoutSession(req.params.id)
  if (session.metadata?.memberId && String(session.metadata.memberId) !== String(req.member.sub)) {
    return res.status(403).json({ message: 'You cannot view this order.' })
  }

  const result = await recordStripeSession(session, req)
  return res.json(result)
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
    req,
  })
  return res.json({ free: false, ...session })
}))

// ---------------------------------------------------------------------------
// Free orders only — every paid order is written exclusively by Stripe data
// ---------------------------------------------------------------------------

router.post('/payments', requireMember, asyncRoute(async (req, res) => {
  const product = req.body?.productId
    ? await findById(collections.products(), req.body.productId)
    : null
  const free = String(product?.badge || '').toLowerCase() === 'free'
    || Number(product?.price) === 0

  if (!product || !free) {
    return res.status(400).json({ message: 'Only free applications can be added without Stripe.' })
  }

  const customer = String(req.member?.email || '').trim().slice(0, 80)
  if (!customer) return res.status(401).json({ message: 'Sign in again to claim this application.' })

  const doc = {
    id: await nextOrderId(),
    customer,
    product: String(product.title).trim().slice(0, 120),
    amount: 0,
    currency: 'USD',
    method: 'Free',
    status: 'Completed',
    date: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
    source: 'free-order',
    productId: product._id,
    soldCounted: true,
  }

  await collections.payments().insertOne(doc)
  await collections.products().updateOne({ _id: product._id }, { $inc: { sold: 1 } })
  await emitProducts(req)
  await emitPayments(req)
  return res.status(201).json(publicPayment(doc))
}))

// ---------------------------------------------------------------------------
// Admin auth / users / payments
// ---------------------------------------------------------------------------

router.post('/admin/login', asyncRoute(async (req, res) => {
  const email = String(req.body?.email || '').trim()
  const password = String(req.body?.password || '')

  // The original single admin account remains available, so existing installs
  // can still sign in before any users exist in the database.
  if (email.toLowerCase() === config.adminEmail.toLowerCase() && password === config.adminPassword) {
    return res.json({
      token: signAdminToken(config.adminEmail),
      admin: { email: config.adminEmail, name: 'Admin', scope: 'all' },
    })
  }

  const user = await findAccountByEmail(email)
  if (!user || !await passwordMatches(user, password)) {
    return res.status(401).json({ message: 'Invalid email or password.' })
  }

  if (user.emailVerified === false) {
    return res.status(403).json({ message: 'Please verify your email before signing in to the admin panel.' })
  }
  if (user.status === 'Suspended' || (!user.status && user.active === false)) {
    return res.status(403).json({ message: 'This admin account is suspended. Please contact support.' })
  }
  if (!isActiveAdmin(user)) {
    return res.status(403).json({ message: 'This account does not have admin access.' })
  }

  return res.json({
    token: signAdminToken(user.email, user),
    admin: {
      email: user.email,
      name: user.name || user.username || 'Admin',
      role: 'Admin',
      scope: adminScope(user.email),
    },
  })
}))

router.get('/admin/payments', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
  const fresh = await freshAdminPayments(req)
  res.json({ ...fresh.sync, payments: fresh.payments })
}))

router.get('/admin/tickets', requireAdmin, requireFullAdmin, asyncRoute(async (_req, res) => {
  res.json(await listTickets())
}))

router.patch('/admin/tickets/:id', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.tickets(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Ticket not found.' })

  const patch = {}
  if (req.body?.status !== undefined) {
    const status = String(req.body.status).trim()
    if (!['Open', 'In Progress', 'Closed'].includes(status)) {
      return res.status(400).json({ message: 'Choose a valid ticket status.' })
    }
    patch.status = status
  }
  if (req.body?.response !== undefined) {
    const response = String(req.body.response).trim()
    if (response.length > 4000) {
      return res.status(400).json({ message: 'Keep the response under 4000 characters.' })
    }
    patch.response = response
    patch.respondedAt = new Date()
  }
  if (!Object.keys(patch).length) {
    return res.status(400).json({ message: 'There is nothing to update on this ticket.' })
  }

  if (patch.status === 'Closed') patch.closedAt = new Date()
  if (patch.status === 'Open' || patch.status === 'In Progress') patch.closedAt = null
  patch.updatedAt = new Date()

  await collections.tickets().updateOne({ _id: existing._id }, { $set: patch })
  const updated = publicTicket({ ...existing, ...patch })
  await emitTickets(req)
  emitToMember(req, existing.memberId, 'ticket:updated', updated)
  return res.json(updated)
}))

router.delete('/admin/tickets/:id', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
  const existing = await findById(collections.tickets(), req.params.id)
  if (!existing) return res.status(404).json({ message: 'Ticket not found.' })

  await collections.tickets().deleteOne({ _id: existing._id })
  await emitTickets(req)
  emitToMember(req, existing.memberId, 'ticket:deleted', { id: String(existing._id) })
  return res.json({ ok: true })
}))

router.get('/admin/users', requireAdmin, requireFullAdmin, asyncRoute(async (_req, res) => {
  res.json(await listUsers())
}))

router.post('/admin/users', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
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
    passwordHash: await bcrypt.hash(password, 10),
    passwordVersion: 0,
    // Admin-created accounts get their credentials directly, so no email link
    // is required for them.
    emailVerified: true,
    role,
    status: 'Active',
    joined: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
  }
  await collections.users().insertOne(doc)
  await emitUsers(req)
  return res.status(201).json(publicUser(doc))
}))

router.patch('/admin/users/:id', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
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
    patch.passwordHash = await bcrypt.hash(password, 10)
    patch.passwordVersion = Number(existing.passwordVersion || 0) + 1
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

router.delete('/admin/users/:id', requireAdmin, requireFullAdmin, asyncRoute(async (req, res) => {
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
