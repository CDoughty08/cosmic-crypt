import * as crypto from 'crypto';

import * as promise from 'bluebird';

// Helper file to return typed promisified crypto functions

export type randomBytesType = (size: number) => promise<Buffer>;
export type pbkdf2Type      = (password: string | Buffer, salt: string | Buffer, iterations: number, keyLength: number, digest: string) => promise<Buffer>;

export const randomBytes: randomBytesType = promise.promisify(crypto.randomBytes);
export const pbkdf2: pbkdf2Type           = promise.promisify(crypto.pbkdf2);

export { pbkdf2Sync, randomBytes as randomBytesSync } from 'crypto';
