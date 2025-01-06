import { z } from 'zod'

export const firebaseOrgCreate = z.object({
  orgName: z.string(),
  firebaseOrgId: z.string(),
  role: z.string(),
  createdByUserId: z.string(),
});

export const firebaseUserCreate = z.object({
  email: z.string().email({ message: 'Invalid email address' }),
  password: z.string().min(4, { message: 'Password must be at least 4 characters long' }),
});
