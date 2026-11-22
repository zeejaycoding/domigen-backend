import Stripe from 'stripe'
import { config } from './config.js'
import { collections } from './db.js'
import { findById, nextOrderId } from './helpers.js'
import { listPayments, listProducts } from './repository.js'

const stripe = config.stripeSecretKey ? new Stripe(config.stripeSecretKey) : null

export function paymentsEnabled() {
  return Boolean(stripe && config.stripePublishableKey)
}

export function paymentPublicConfig() {
  return {
    enabled: paymentsEnabled(),
    publishableKey: config.stripePublishableKey || '',
  }
}

export async function retrieveCheckoutSession(sessionId) {
  if (!stripe) throw new Error('Online payments are not configured. Please contact support.')
  return stripe.checkout.sessions.retrieve(sessionId, {
    expand: ['line_items.data.price.product'],
  })
}

async function emitPaymentUpdates(req) {
  const io = req?.app?.get?.('io')
  if (!io) return
  io.to('admin').emit('payments', await listPayments())
  io.emit('products', await listProducts())
}

export async function createCheckoutSession({ product, member, req }) {
  if (!stripe) {
    throw new Error('Online payments are not configured. Please contact support.')
  }

  const unitAmount = Math.round(Number(product.price) * 100)
  if (!Number.isInteger(unitAmount) || unitAmount <= 0) {
    throw new Error('This product has no valid price for online payment.')
  }

  const successUrl = `${config.frontendUrl}${config.checkoutSuccessPath}`
    + `${config.checkoutSuccessPath.includes('?') ? '&' : '?'}session_id={CHECKOUT_SESSION_ID}`

  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    // Stripe 2026+ removed `payment_method_types`. This filter keeps the
    // checkout to cards (including the Apple Pay wallet when the domain is
    // verified) and prevents other methods such as PayPal from appearing.
    allowed_payment_method_types: ['card'],
    line_items: [{
      quantity: 1,
      price_data: {
        currency: 'usd',
        unit_amount: unitAmount,
        product_data: {
          name: String(product.title || 'DOMIGEN product').slice(0, 120),
          description: String(product.description || product.game || 'DOMIGEN application').slice(0, 300),
        },
      },
    }],
    customer_email: String(member?.email || '').trim() || undefined,
    client_reference_id: String(product.id),
    metadata: {
      productId: String(product.id),
      memberId: String(member?.sub || ''),
    },
    success_url: successUrl,
    cancel_url: `${config.frontendUrl}${config.checkoutCancelPath}`,
  })

  // No local order is written here. The admin only gets a record after Stripe
  // itself reports the session as paid.
  return { id: session.id, url: session.url }
}

function sessionSummary(session) {
  const line = session?.line_items?.data?.[0]
  const product = String(
    line?.price?.product?.name
    || line?.description
    || '',
  ).trim().slice(0, 120)

  return {
    paid: session?.payment_status === 'paid',
    recorded: false,
    changed: false,
    counted: false,
    status: '',
    paymentStatus: String(session?.payment_status || ''),
    stripeStatus: String(session?.status || ''),
    product,
    amount: Number(session?.amount_total || 0) / 100,
    currency: String(session?.currency || 'usd').toUpperCase(),
    method: '',
    cardBrand: '',
    cardLast4: '',
    paymentIntentId: '',
  }
}

/** Read the authoritative payment data from Stripe, not from local metadata. */
async function readStripePayment(session) {
  if (!stripe) throw new Error('Online payments are not configured. Please contact support.')

  const detailed = await stripe.checkout.sessions.retrieve(String(session.id), {
    expand: ['line_items.data.price.product'],
  })

  const paymentIntentId = String(detailed.payment_intent || '')
  if (!paymentIntentId) throw new Error('Stripe did not attach a payment intent to this checkout.')

  const intent = await stripe.paymentIntents.retrieve(paymentIntentId, {
    expand: ['latest_charge'],
  })
  if (intent.status !== 'succeeded') {
    throw new Error(`Stripe reports payment intent status "${intent.status}".`)
  }

  const charge = typeof intent.latest_charge === 'string'
    ? await stripe.charges.retrieve(intent.latest_charge)
    : intent.latest_charge
  const card = charge?.payment_method_details?.card
  if (!card) throw new Error('Stripe did not return card details for this payment.')

  const walletType = String(card.wallet?.type || '')
  const method = walletType === 'apple_pay' ? 'Apple Pay' : 'Card'
  const refunded = Boolean(
    charge?.refunded
    || Number(charge?.amount_refunded || 0) > 0,
  )

  const line = detailed.line_items?.data?.[0]
  const product = String(
    line?.price?.product?.name
    || line?.description
    || '',
  ).trim().slice(0, 120)
  if (!product) throw new Error('Stripe did not return a product name for this payment.')

  const customer = String(
    detailed.customer_details?.email
    || detailed.customer_email
    || '',
  ).trim().slice(0, 80)
  if (!customer) throw new Error('Stripe did not return a customer email for this payment.')

  const created = new Date(Number(detailed.created || 0) * 1000)
  const date = Number.isNaN(created.getTime())
    ? new Date().toISOString().slice(0, 10)
    : created.toISOString().slice(0, 10)
  const status = refunded ? 'Refunded' : 'Completed'

  const details = {
    customer,
    product,
    amount: Number(detailed.amount_total || 0) / 100,
    currency: String(detailed.currency || 'usd').toUpperCase(),
    method,
    date,
    status,
    stripeSessionId: detailed.id,
    stripePaymentIntentId: intent.id,
    stripeChargeId: String(charge?.id || ''),
    stripePaymentStatus: String(detailed.payment_status || ''),
    stripeCheckoutStatus: String(detailed.status || ''),
    stripeCardBrand: String(card.brand || ''),
    stripeCardLast4: String(card.last4 || ''),
    stripeCreated: Number.isNaN(created.getTime()) ? '' : created.toISOString(),
    source: 'stripe',
    soldCounted: true,
  }

  return {
    details,
    status,
    summary: {
      paid: detailed.payment_status === 'paid',
      recorded: false,
      changed: false,
      counted: false,
      status: refunded ? 'Refunded' : 'Completed',
      paymentStatus: String(detailed.payment_status || ''),
      stripeStatus: String(detailed.status || ''),
      product,
      amount: details.amount,
      currency: details.currency,
      method,
      cardBrand: String(card.brand || ''),
      cardLast4: String(card.last4 || ''),
      paymentIntentId: intent.id,
    },
  }
}

const TRACKED_PAYMENT_FIELDS = [
  'customer',
  'product',
  'amount',
  'currency',
  'method',
  'date',
  'stripeSessionId',
  'stripePaymentIntentId',
  'stripeChargeId',
  'stripePaymentStatus',
  'stripeCheckoutStatus',
  'stripeCardBrand',
  'stripeCardLast4',
  'stripeCreated',
  'source',
  'soldCounted',
  'status',
]

async function applyStripePayment(existing, info, req) {
  const patch = {}
  for (const field of TRACKED_PAYMENT_FIELDS) {
    if (String(existing[field] ?? '') !== String(info.details[field] ?? '')) {
      patch[field] = info.details[field]
    }
  }

  const changed = Object.keys(patch).length > 0
  if (changed) {
    await collections.payments().updateOne({ _id: existing._id }, { $set: patch })
  }

  const shouldCount = !existing.soldCounted
    && existing.status !== 'Completed'
    && existing.status !== 'Refunded'

  let countedSale = false
  if (shouldCount) {
    const productId = existing.productId
      || (await findById(collections.products(), info.productId))?._id
      || (await collections.products().findOne({ title: existing.product }))?._id
    if (productId) {
      await collections.products().updateOne({ _id: productId }, { $inc: { sold: 1 } })
      await collections.payments().updateOne(
        { _id: existing._id },
        { $set: { soldCounted: true, productId } },
      )
      countedSale = true
    }
  }

  if (changed || countedSale) await emitPaymentUpdates(req)
  return changed || countedSale
}

/**
 * The only writer for paid orders. Every field comes from Stripe itself.
 * Safe to call from the success page, the webhook, or an admin sync.
 */
export async function recordStripeSession(session, req) {
  if (!session) throw new Error('Stripe did not return a checkout session.')

  if (session.payment_status !== 'paid') {
    return sessionSummary(session)
  }

  const info = await readStripePayment(session)
  info.productId = String(session.metadata?.productId || session.client_reference_id || '')
  const existing = await collections.payments().findOne({
    stripeSessionId: info.details.stripeSessionId,
  })

  if (existing) {
    const changed = await applyStripePayment(existing, info, req)
    return { ...info.summary, recorded: true, changed }
  }

  const productId = info.productId
    ? (await findById(collections.products(), info.productId))?._id
    : null
  const productDoc = productId
    ? { _id: productId }
    : await collections.products().findOne({ title: info.details.product })

  const doc = {
    id: await nextOrderId(),
    createdAt: new Date(),
    completedAt: new Date(),
    ...info.details,
    status: info.status,
    ...(session.metadata?.memberId ? { memberId: String(session.metadata.memberId) } : {}),
    ...(productDoc?._id ? { productId: productDoc._id } : {}),
  }

  let counted = false
  try {
    await collections.payments().insertOne(doc)
    if (productDoc?._id) {
      await collections.products().updateOne({ _id: productDoc._id }, { $inc: { sold: 1 } })
      counted = true
    }
  } catch (error) {
    if (error?.code !== 11000) throw error
    const raced = await collections.payments().findOne({
      stripeSessionId: info.details.stripeSessionId,
    })
    if (!raced) throw error
    const changed = await applyStripePayment(raced, info, req)
    return { ...info.summary, recorded: true, changed }
  }

  await emitPaymentUpdates(req)
  return { ...info.summary, recorded: true, changed: true, counted }
}

/**
 * Pull every Checkout Session from Stripe. This is the authoritative source
 * for the admin list, so no webhook or local pending-order guess is needed.
 */
export async function syncStripePayments(req) {
  if (!stripe) throw new Error('Online payments are not configured. Please contact support.')

  let checked = 0
  let paid = 0
  let updated = 0
  const seenSessionIds = []
  const sessions = stripe.checkout.sessions.list({ limit: 100 })

  for await (const session of sessions) {
    checked += 1
    seenSessionIds.push(String(session.id))
    if (session.payment_status !== 'paid') continue
    paid += 1
    const result = await recordStripeSession(session, req)
    if (result.changed || result.counted) updated += 1
  }

  // A paid record must carry the Stripe session that produced it. This removes
  // old manual/fake rows and any mirror row that no longer exists in Stripe.
  const removedLegacy = await collections.payments().deleteMany({
    method: { $ne: 'Free' },
    $or: [
      { stripeSessionId: { $exists: false } },
      { stripeSessionId: { $in: [null, ''] } },
    ],
  })

  const removedStale = seenSessionIds.length
    ? await collections.payments().deleteMany({
      source: 'stripe',
      stripeSessionId: { $nin: seenSessionIds },
    })
    : { deletedCount: 0 }

  const removed = removedLegacy.deletedCount + removedStale.deletedCount
  if (removed) await emitPaymentUpdates(req)

  return {
    checked,
    paid,
    updated,
    removed,
    stripeConfigured: true,
    syncedAt: new Date().toISOString(),
  }
}

export async function handleStripeWebhook(req, res) {
  if (!stripe || !config.stripeWebhookSecret) {
    return res.status(503).json({ message: 'Stripe webhooks are not configured.' })
  }

  let event
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      req.headers['stripe-signature'],
      config.stripeWebhookSecret,
    )
  } catch (error) {
    return res.status(400).json({ message: `Webhook signature failed: ${error.message}` })
  }

  try {
    if (['checkout.session.completed', 'checkout.session.async_payment_succeeded'].includes(event.type)) {
      await recordStripeSession(event.data.object, req)
    }
    return res.json({ received: true })
  } catch (error) {
    console.error('Stripe webhook error:', error)
    return res.status(500).json({ message: error.message || 'Webhook processing failed.' })
  }
}
