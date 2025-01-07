import { z } from 'zod'

export const firebaseOrgCreate = z.object({
  orgName: z.string(),
  firebaseOrgId: z.string(),
  role: z.string(),
  createdByUserId: z.string(),
});

export const firebaseUserCreate = z.object({
  id: z.string(),
  data: z.object({
    id: z.string(),
    email: z.string().email({ message: 'Invalid email address' }),
    object: z.string(),
    last_name: z.string().nullable(),
    created_at: z.string(),
    first_name: z.string().nullable(),
    updated_at: z.string(),
    email_verified: z.boolean(),
    profile_picture_url: z.string().nullable(),
  }),
  event: z.string(),
  created_at: z.string(),
});
