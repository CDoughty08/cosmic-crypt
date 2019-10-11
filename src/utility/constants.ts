export const HMAC_ALGORITHM = 'sha512';
export const ENCRYPT_ALGORITHM = 'aes-256-cbc';
export const DERIVE_ALGORITHM = 'sha512';

export const PBKDF2_ROUNDS = 10000;

export const PASS_KEY_SIZE = 32;

export const IV_LENGTH = 16;
export const PASS_LENGTH = 64;
export const HMAC_LENGTH = 64;
export const SALT_LENGTH = 32;

export const ROUNDS_SIZE = 4;

// tslint:disable-next-line:no-var-requires
export const VERSION = require('../../package.json').version as string;
export const MARKER = 'CCRYPT' as string;
export const MARKER_BUFFER = Buffer.from(MARKER).toString('hex');
