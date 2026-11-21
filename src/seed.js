import { closeDatabase, collections, connectDatabase } from './db.js'
import { DEFAULT_SETTINGS } from './helpers.js'

export async function seedDatabase() {
  await connectDatabase()

  // There is no mock catalogue, payment history or account data. Products are
  // created in admin, orders come from Stripe checkout or free claims, and the
  // existing `users` collection belongs to the site owner and is never touched.

  const settingsCount = await collections.settings().countDocuments({ key: 'site' })
  if (settingsCount === 0) {
    await collections.settings().insertOne({ key: 'site', ...DEFAULT_SETTINGS })
    console.log('Seeded default site settings.')
  }
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  seedDatabase()
    .then(async () => {
      await closeDatabase()
      process.exit(0)
    })
    .catch(async (error) => {
      console.error('Seed failed:', error.message)
      await closeDatabase()
      process.exit(1)
    })
}
