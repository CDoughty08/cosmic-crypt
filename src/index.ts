export { CosmicCrypt } from './cosmic-crypt';
export { encrypt, encryptSync, EncryptErrorCode } from './crypt/encrypt';
export { decrypt, decryptSync, DecryptErrorCode } from './crypt/decrypt';
export { UnpackErrorCode } from './utility';

import { encryptSync } from './crypt/encrypt';

import { decryptSync } from './crypt/decrypt';

const text = Buffer.from('Test Data!');
const password = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12');
const iv = Buffer.from('1234123412341234');
const salt = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');

const encrypted = encryptSync(text, password, iv, salt);

const decrypted = decryptSync(encrypted, password);

console.log(decrypted.toString());