import {
  HMAC_LENGTH,
  IV_LENGTH,
  SALT_LENGTH
} from './';

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  hmac: Buffer;
  salt: Buffer;
}

export enum UnpackErrorCode {
  INVALID_META_LENGTH,
  INVALID_ENCRYPTED_DATA
}

export function unpack(buffer: Buffer): EncryptedData {
  const metaLength = ( HMAC_LENGTH * 2 ) + ( IV_LENGTH * 2) + ( SALT_LENGTH * 2);
  if ( buffer.length < metaLength ) {
    throw { code: UnpackErrorCode.INVALID_META_LENGTH, message: 'Decrypt Error' };
  }

  let offset = 0;
  const iv = buffer.slice(offset, IV_LENGTH * 2);

  offset += IV_LENGTH * 2;
  const salt = buffer.slice(offset, SALT_LENGTH * 2 + offset);

  offset += SALT_LENGTH * 2;
  const hmac = buffer.slice(offset, HMAC_LENGTH * 2 + offset);

  offset += HMAC_LENGTH * 2;
  const encrypted = buffer.slice(offset);

  if ( encrypted.length % 32 !== 0 ) {
    throw { code: UnpackErrorCode.INVALID_ENCRYPTED_DATA, message: 'Decrypt Error' };
  }

  return {
    encrypted,
    hmac,
    iv,
    salt
  };
}
