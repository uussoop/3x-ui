import { z } from 'zod';

// ProbeTargetSchema is the health-probe destination a VPN exit dials through
// its own tunnel.
//
// The value ends up in a dial call, so it must not be able to name a scheme or
// a path: "https://x/y" or "example.com:80:90" would fail later as a confusing
// dial error instead of here as a rejected field. Empty means "no probe" — a
// tunnel the panel does not measure rather than one measured at a destination
// nobody chose.
export const ProbeTargetSchema = z
  .string()
  .default('')
  .refine(
    (value) => {
      const v = value.trim();
      if (v === '') return true;
      const match = /^(\[[^\]]+\]|[^[\]\s:]+):(\d{1,5})$/.exec(v);
      if (!match) return false;
      const port = Number(match[2]);
      return port > 0 && port <= 65535;
    },
    { message: 'probe target must be host:port' },
  );
