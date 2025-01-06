import { z } from 'zod'

export const firebaseOrgCreate = z.object({
  orgName: z.string(),
  firebaseOrgId: z.string(),
  role: z.string(),
  createdByUserId: z.string(),
})