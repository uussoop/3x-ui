import { z } from 'zod';

export const OpenVPNClientSchema = z.object({
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
});

export const OpenVPNInboundSettingsSchema = z.object({
  mode: z.enum(['server', 'client']).default('server'),
  dev: z.string().default('tun'),
  port: z.number().int().default(1194),
  proto: z.enum(['udp', 'tcp']).default('udp'),
  ca: z.string().default(''),
  cert: z.string().default(''),
  key: z.string().default(''),
  dh: z.string().default(''),
  server: z.string().default('10.8.0.0 255.255.255.0'),
  ifconfigPoolPersist: z.string().default(''),
  keepalive: z.string().default('10 120'),
  cipher: z.string().default('AES-256-CBC'),
  compLzo: z.enum(['yes', 'no', 'adaptive']).default('adaptive'),
  user: z.string().default('nobody'),
  group: z.string().default('nogroup'),
  status: z.string().default('/var/log/openvpn-status.log'),
  verb: z.number().int().default(3),
  clients: z.array(OpenVPNClientSchema).default([]),
  profile: z.string().default(''),
});

export type OpenVPNInboundSettings = z.infer<typeof OpenVPNInboundSettingsSchema>;
export type OpenVPNClient = z.infer<typeof OpenVPNClientSchema>;
