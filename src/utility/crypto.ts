import * as crypto from 'crypto';

import * as promise from 'bluebird';

// Helper file to return typed promisified crypto functions

export type randomBytesType = (size: number) => promise<Buffer>;
export type pbkdf2Type      = (password: string | Buffer, salt: string | Buffer, iterations: number, keyLength: number, digest: string) => promise<Buffer>;
export type scryptType      = (password: crypto.BinaryLike, salt: crypto.BinaryLike, keyLength: number, options: crypto.ScryptOptions) => promise<Buffer>;
export type generateX25519KeyPairType = () => promise<crypto.ECKeyPairKeyObjectOptions>;

export const randomBytes: randomBytesType                     = promise.promisify(crypto.randomBytes);
export const pbkdf2: pbkdf2Type                               = promise.promisify(crypto.pbkdf2);
export const scrypt: scryptType                               = promise.promisify(crypto.scrypt);
export const generateX25519KeyPair: generateX25519KeyPairType = promise.promisify((crypto.generateKeyPair as any).bind(null, 'x25519', {}), { multiArgs: true });

export { pbkdf2Sync, scryptSync, ScryptOptions, randomBytes as randomBytesSync } from 'crypto';
