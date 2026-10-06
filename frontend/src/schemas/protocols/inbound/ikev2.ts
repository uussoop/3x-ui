import { z } from 'zod';

export const IKEv2ClientSchema = z.object({
  username: z.string().default(''),
  password: z.string().default(''),
  email: z.string().default(''),
  limitIp: z.number().int().min(0).default(0),
  totalGB: z.number().int().min(0).default(0),
  expiryTime: z.number().int().default(0),
  enable: z.boolean().default(true),
  tgId: z
    .union([z.number(), z.string()])
    .transform((v) => Number(v) || 0)
    .default(0),
  subId: z.string().default(''),
  comment: z.string().default(''),
  reset: z.number().int().min(0).default(0),
  authMethod: z.enum(['eap-mschapv2', 'cert', 'psk']).default('eap-mschapv2'),
  cert: z.string().default(''),
});

export const IKEv2InboundSettingsSchema = z.object({
  mode: z.enum(['server', 'client']).default('server'),
  localAddr: z.string().default('0.0.0.0'),
  localPort: z.number().int().default(500),
  natTraversal: z.boolean().default(true),
  ikeVersion: z.number().int().default(2),
  encryption: z.string().default('aes256-sha256-modp2048'),
  caCert: z.string().default(''),
  serverCert: z.string().default(''),
  serverKey: z.string().default(''),
  clients: z.array(IKEv2ClientSchema).default([]),
});

export type IKEv2InboundSettings = z.infer<typeof IKEv2InboundSettingsSchema>;
export type IKEv2Client = z.infer<typeof IKEv2ClientSchema>;
