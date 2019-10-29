
import { HMAC_LENGTH, MARKER, SALT_LENGTH } from '../common/constants';

export const SCRYPT_CIPHER = 'aes-256-cbc';

export const IV_LENGTH = 16;
export const PASS_LENGTH = 64;

export const ScryptHeaderSize = (MARKER.length * 2) + (IV_LENGTH * 2);
export const ScryptTrailerSize = (HMAC_LENGTH * 2) + (SALT_LENGTH * 2);

export interface EncryptedData {
  headerRaw: Buffer;
  encrypted: Buffer;
  iv: Buffer;
  hmac: Buffer;
  salt: Buffer;
}
