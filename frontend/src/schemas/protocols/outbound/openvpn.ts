import { z } from 'zod';

import { ProbeTargetSchema } from '@/schemas/primitives/probe';

export const OpenVPNOutboundSettingsSchema = z.object({
  mode: z.enum(['client']).default('client'),
  config: z.string().default(''),
  authUserPass: z.string().default(''),
  dev: z.string().default('tun'),
  proto: z.enum(['udp', 'tcp']).default('udp'),
  remote: z.string().default(''),
  port: z.number().int().default(1194),
  cipher: z.string().default('AES-256-CBC'),
  auth: z.string().default('SHA512'),
  compLzo: z.enum(['yes', 'no', 'adaptive']).default('adaptive'),
  verb: z.number().int().default(3),
  ca: z.string().default(''),
  cert: z.string().default(''),
  key: z.string().default(''),
  tlsAuth: z.string().default(''),
  probeTarget: ProbeTargetSchema,
  probeDevice: z.string().default(''),
});

export type OpenVPNOutboundSettings = z.infer<typeof OpenVPNOutboundSettingsSchema>;
