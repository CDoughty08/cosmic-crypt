import * as crypto from 'crypto';
import { promisify } from 'util';

// Helper file to return typed promisified crypto functions

export type randomBytesType = (size: number) => Promise<Buffer>;
export type randomFillType  = (buffer: Buffer, offset?: number, size?: number) => Promise<Buffer>;
export type pbkdf2Type      = (password: string | Buffer, salt: string | Buffer, iterations: number, keyLength: number, digest: string) => Promise<Buffer>;

export const randomBytes: randomBytesType = promisify(crypto.randomBytes);
export const randomFill: randomFillType = (buffer, offset?, size?) =>
  new Promise<Buffer>((resolve, reject) =>
    crypto.randomFill(buffer, offset ?? 0, size ?? buffer.length, (err, buf) =>
      /* c8 ignore next */ err ? reject(err) : resolve(buf as Buffer)));
export const pbkdf2: pbkdf2Type           = promisify(crypto.pbkdf2);

export { pbkdf2Sync, randomBytes as randomBytesSync } from 'crypto';
