import dns from 'node:dns/promises';
import { isIP } from 'node:net';

/**
 * Checks whether an IPv4 address belongs to a private, loopback, link-local,
 * multicast, or reserved range.
 */
export function isPrivateIPv4(ip) {
  const parts = ip.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return true; // malformed, treat as unsafe
  }

  const [a, b] = parts;

  // 0.0.0.0/8 - Current network
  if (a === 0) return true;
  // 10.0.0.0/8 - Private-Use
  if (a === 10) return true;
  // 100.64.0.0/10 - Shared Address Space
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 - Loopback
  if (a === 127) return true;
  // 169.254.0.0/16 - Link-Local / Cloud Metadata (e.g. 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 - Private-Use
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24 - IETF Protocol Assignments
  if (a === 192 && b === 0 && parts[2] === 0) return true;
  // 192.0.2.0/24 - TEST-NET-1
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  // 192.168.0.0/16 - Private-Use
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 - Benchmarking
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 - TEST-NET-2
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  // 203.0.113.0/24 - TEST-NET-3
  if (a === 203 && b === 0 && parts[2] === 113) return true;
  // 224.0.0.0/4 - Multicast
  if (a >= 224 && a <= 239) return true;
  // 240.0.0.0/4 - Reserved
  if (a >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address belongs to a private, loopback, link-local,
 * multicast, or reserved range.
 */
export function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  // ::1 loopback
  if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
  // :: unspecified
  if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
  // IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    const v4part = normalized.replace('::ffff:', '');
    if (isIP(v4part) === 4) return isPrivateIPv4(v4part);
  }
  // fc00::/7 - Unique local addresses (fc00:: - fdff::)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
  // fe80::/10 - Link-local
  if (/^fe[89ab]/i.test(normalized)) return true;
  // ff00::/8 - Multicast
  if (normalized.startsWith('ff')) return true;

  return false;
}

/**
 * Comprehensive SSRF and URL validation for Nector.
 * Ensures the target is an authorized, publicly resolvable HTTP/HTTPS destination.
 */
export async function validateScanTarget(rawInput) {
  if (!rawInput || typeof rawInput !== 'string') {
    return { valid: false, error: 'A target URL must be provided.' };
  }

  const trimmed = rawInput.trim();
  if (trimmed.length > 2048) {
    return { valid: false, error: 'URL exceeds maximum length of 2048 characters.' };
  }

  // Reject non-HTTP schemes early (ftp://, file://, ssh://, etc.)
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && !/^https?:\/\//i.test(trimmed)) {
    return { valid: false, error: 'Only http: and https: protocols are permitted.' };
  }

  // Prepend scheme if missing
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { valid: false, error: 'Malformed URL format.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only http: and https: protocols are permitted.' };
  }

  // Reject embedded credentials (http://user:pass@host)
  if (parsed.username || parsed.password) {
    return { valid: false, error: 'Embedded credentials are prohibited.' };
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();

  // Block localhost and common local names
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname === 'metadata.google.internal' ||
    hostname === '169.254.169.254'
  ) {
    return {
      valid: false,
      error: 'Prohibited scan target: Localhost and internal network addresses are blocked for safety.',
    };
  }

  // Check if target is a direct IP literal
  const ipVer = isIP(hostname);
  if (ipVer === 4) {
    if (isPrivateIPv4(hostname)) {
      return {
        valid: false,
        error: 'Prohibited scan target: Private and loopback IP addresses cannot be scanned.',
      };
    }
  } else if (ipVer === 6) {
    if (isPrivateIPv6(hostname)) {
      return {
        valid: false,
        error: 'Prohibited scan target: Private and loopback IPv6 addresses cannot be scanned.',
      };
    }
  } else {
    // Hostname: resolve DNS to prevent DNS rebinding / internal routing
    let records = [];
    try {
      records = await dns.lookup(hostname, { all: true });
    } catch {
      try {
        // Fallback 1: standard IPv4 lookup without AI_ALL flag
        const single = await dns.lookup(hostname, { family: 4 });
        if (single && single.address) {
          records = [{ family: 4, address: single.address }];
        }
      } catch {
        try {
          // Fallback 2: direct resolve4 query
          const v4List = await dns.resolve4(hostname);
          records = v4List.map((addr) => ({ family: 4, address: addr }));
        } catch (resolveErr) {
          return {
            valid: false,
            error: `Unable to resolve website domain "${hostname}". Please verify that the domain is spelled correctly and has active, public DNS records.`,
          };
        }
      }
    }

    if (!records || records.length === 0) {
      return {
        valid: false,
        error: `Could not resolve any IP address for domain: ${hostname}`,
      };
    }

    for (const rec of records) {
      if (rec.family === 4 && isPrivateIPv4(rec.address)) {
        return {
          valid: false,
          error: `Prohibited scan target: Domain resolves to private/internal IP address (${rec.address}).`,
        };
      }
      if (rec.family === 6 && isPrivateIPv6(rec.address)) {
        return {
          valid: false,
          error: `Prohibited scan target: Domain resolves to internal IPv6 address (${rec.address}).`,
        };
      }
    }
  }

  const cleanPath = parsed.pathname === '/' ? '' : parsed.pathname;
  return {
    valid: true,
    normalizedUrl: `${parsed.protocol}//${parsed.host}${cleanPath}${parsed.search || ''}`,
    hostname: parsed.hostname,
    protocol: parsed.protocol,
  };
}

export default validateScanTarget;
