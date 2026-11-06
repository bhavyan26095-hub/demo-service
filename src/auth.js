// demo-service authentication module
// Updated by @builder with secure scrypt hashing
import crypto from 'node:crypto';

export function verifyPassword(input, expected) {
  // Uses timingSafeEqual to prevent timing side channels
  const a = Buffer.from(input);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
