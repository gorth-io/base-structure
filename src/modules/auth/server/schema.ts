import { z } from "zod";

const boundedToken = z
  .string()
  .min(1)
  .max(32_768)
  .regex(/^[\x21-\x7e]+$/);
export const oauthTokenSchema = z.object({
  access_token: boundedToken,
  refresh_token: boundedToken.optional(),
  id_token: boundedToken.optional(),
  token_type: z
    .string()
    .transform((value) => value.toLowerCase())
    .pipe(z.literal("bearer")),
  expires_in: z.number().finite().positive().max(2_592_000),
  refresh_token_expires_in: z
    .number()
    .finite()
    .positive()
    .max(31_536_000)
    .optional(),
});

export const oauthIdentitySchema = z.object({
  sub: z.string().min(1).max(255),
  name: z.string().max(255).optional(),
  email: z.email().max(255).optional(),
  email_verified: z.boolean().optional(),
  preferred_username: z
    .string()
    .max(64)
    .toLowerCase()
    .regex(/^[a-z0-9._-]+$/)
    .nullable()
    .optional(),
  picture: z.url().max(2048).nullable().optional(),
});

const randomValue = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
export const oauthCredentialsSchema = z.object({
  accessToken: boundedToken,
  refreshToken: boundedToken.optional(),
  accessExpiresAt: z.number().finite().positive(),
  refreshExpiresAt: z.number().finite().positive().optional(),
  subject: z.string().min(1).max(255),
  nonce: randomValue,
});
export const loginTransactionSchema = z.object({
  state: randomValue,
  verifier: randomValue,
  nonce: randomValue,
  issuer: z.string().max(2048),
  clientId: z.string().min(1).max(255),
  redirectUri: z.string().max(2048),
  returnTo: z.string().max(2048),
  expiresAt: z.number().safe().positive(),
});
