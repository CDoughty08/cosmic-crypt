import * as crypto from 'crypto';
import { promisify } from 'util';

// Helper file to return typed promisified crypto functions

export type randomBytesType = (size: number) => Promise<Buffer>;
export type randomFillType  = (buffer: Buffer, offset?: number, size?: number) => Promise<Buffer>;
export type pbkdf2Type      = (password: string | Buffer, salt: string | Buffer, iterations: number, keyLength: number, digest: string) => Promise<Buffer>;

export const randomBytes: randomBytesType = promisify(crypto.randomBytes);

// Wrapper for randomFill to match expected return type
export const randomFill: randomFillType = async (buffer: Buffer, offset?: number, size?: number) => {
  // Cast to any to handle the overloaded function signatures
  const promisifiedRandomFill = promisify(crypto.randomFill as any);
  if (offset !== undefined && size !== undefined) {
    await promisifiedRandomFill(buffer, offset, size);
  } else if (offset !== undefined) {
    await promisifiedRandomFill(buffer, offset);
  } else {
    await promisifiedRandomFill(buffer);
  }
  return buffer;
};

export const pbkdf2: pbkdf2Type = promisify(crypto.pbkdf2);

export { pbkdf2Sync, randomBytes as randomBytesSync } from 'crypto';
