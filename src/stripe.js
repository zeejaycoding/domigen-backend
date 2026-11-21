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
  return stripe.checkout.sessions.retrieve(sessionId)
}

async function emitPaymentUpdates(req) {
  const io = req?.app?.get?.('io')
  if (!io) return
  io.to('admin').emit('payments', await listPayments())
  io.emit('products', await listProducts())
}

export async function createCheckoutSession({ product, member, wallet = 'card', req }) {
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
    // Stripe Checkout shows Apple Pay automatically on verified domains and
    // supported devices, alongside normal card entry, with this one type.
    payment_method_types: ['card'],
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
      productTitle: String(product.title || 'DOMIGEN product').slice(0, 120),
      memberId: String(member?.sub || ''),
      customerEmail: String(member?.email || '').trim().slice(0, 80),
      wallet: wallet === 'applepay' ? 'applepay' : 'card',
    },
    success_url: successUrl,
    cancel_url: `${config.frontendUrl}${config.checkoutCancelPath}`,
  })

  // Create the Pending order immediately. The verified webhook (or the
  // trusted success-page lookup) changes it to Completed after payment.
  const pendingOrder = {
    id: await nextOrderId(),
    customer: String(member?.email || 'Member').trim().slice(0, 80) || 'Member',
    product: String(product.title || 'DOMIGEN product').slice(0, 120),
    amount: unitAmount / 100,
    method: wallet === 'applepay' ? 'Apple Pay' : 'Card',
    status: 'Pending',
    date: new Date().toISOString().slice(0, 10),
    createdAt: new Date(),
    stripeSessionId: session.id,
    stripePaymentIntentId: '',
    ...(member?.sub ? { memberId: String(member.sub) } : {}),
  }
  await collections.payments().insertOne(pendingOrder)
  await emitPaymentUpdates(req)

  return { id: session.id, url: session.url }
}

async function markCompleted(orderId, details) {
  const result = await collections.payments().updateOne(
    { _id: orderId, status: { $ne: 'Completed' } },
    {
      $set: {
        ...details,
        status: 'Completed',
        completedAt: new Date(),
      },
    },
  )
  return result.modifiedCount > 0
}

export async function recordPaidSession(session, req) {
  if (session?.payment_status !== 'paid') return false

  const productId = session.metadata?.productId || session.client_reference_id
  const product = productId ? await findById(collections.products(), productId) : null
  const amount = Number(session.amount_total || 0) / 100

  const details = {
    customer: String(
      session.customer_details?.email
      || session.customer_email
      || session.metadata?.customerEmail
      || 'Stripe customer',
    ).slice(0, 80),
    product: String(session.metadata?.productTitle || product?.title || 'DOMIGEN product').slice(0, 120),
    amount,
    method: session.metadata?.wallet === 'applepay' ? 'Apple Pay' : 'Card',
    stripeSessionId: session.id,
    stripePaymentIntentId: String(session.payment_intent || ''),
  }

  const existing = await collections.payments().findOne({ stripeSessionId: session.id })
  let completed = false

  if (existing) {
    completed = await markCompleted(existing._id, details)
  } else {
    const doc = {
      id: await nextOrderId(),
      date: new Date().toISOString().slice(0, 10),
      createdAt: new Date(),
      ...details,
      status: 'Completed',
      completedAt: new Date(),
      ...(session.metadata?.memberId ? { memberId: String(session.metadata.memberId) } : {}),
    }

    try {
      await collections.payments().insertOne(doc)
      completed = true
    } catch (error) {
      if (error?.code !== 11000) throw error
      const raced = await collections.payments().findOne({ stripeSessionId: session.id })
      if (raced) completed = await markCompleted(raced._id, details)
      else throw error
    }
  }

  if (!completed) return false

  if (product?._id) {
    await collections.products().updateOne({ _id: product._id }, { $inc: { sold: 1 } })
  }

  await emitPaymentUpdates(req)
  return true
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
      await recordPaidSession(event.data.object, req)
    }
    return res.json({ received: true })
  } catch (error) {
    console.error('Stripe webhook error:', error)
    return res.status(500).json({ message: 'Webhook processing failed.' })
  }
}
