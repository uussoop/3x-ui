import { z } from 'zod';

import { ProbeTargetSchema } from '@/schemas/primitives/probe';

export const IKEv2OutboundSettingsSchema = z.object({
  mode: z.enum(['client']).default('client'),
  remote: z.string().default(''),
  port: z.number().int().default(500),
  localAddr: z.string().default('0.0.0.0'),
  natTraversal: z.boolean().default(true),
  ikeVersion: z.number().int().default(2),
  encryption: z.string().default('aes256-sha256-modp2048'),
  authMethod: z.enum(['eap-mschapv2', 'cert', 'psk']).default('eap-mschapv2'),
  username: z.string().default(''),
  password: z.string().default(''),
  psk: z.string().default(''),
  caCert: z.string().default(''),
  clientCert: z.string().default(''),
  clientKey: z.string().default(''),
  probeTarget: ProbeTargetSchema,
  probeDevice: z.string().default(''),
});

export type IKEv2OutboundSettings = z.infer<typeof IKEv2OutboundSettingsSchema>;
