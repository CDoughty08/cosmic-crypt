import {
  HMAC_LENGTH,
  IV_LENGTH,
  MARKER,
  ROUNDS_SIZE,
  SALT_LENGTH
} from './';

export interface EncryptedData {
  encrypted: Buffer;
  iv: Buffer;
  hmac: Buffer;
  salt: Buffer;
  rounds: Buffer;
}

export enum UnpackErrorCode {
  MISSING_MARKER,
  INVALID_META_LENGTH,
  INVALID_ENCRYPTED_DATA
}

export function unpack(buffer: Buffer): EncryptedData {
  const metaLength = (ROUNDS_SIZE * 2) + ( MARKER.length * 2) + ( HMAC_LENGTH * 2 ) + ( IV_LENGTH * 2) + ( SALT_LENGTH * 2);
  if ( buffer.length < metaLength ) {
    throw { code: UnpackErrorCode.INVALID_META_LENGTH, message: 'Decrypt Error' };
  }

  if ( Buffer.from(buffer.slice(0, MARKER.length * 2).toString(), 'hex').compare(Buffer.from(MARKER)) !== 0 ) {
    throw { code: UnpackErrorCode.MISSING_MARKER, message: 'Decrypt Error' };
  }

  let offset = MARKER.length * 2;
  const rounds = buffer.slice(offset, (ROUNDS_SIZE * 2) + offset );
  offset += ( ROUNDS_SIZE * 2);

  const iv = buffer.slice(offset, IV_LENGTH * 2 + offset);

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
    rounds,
    salt
  };
}
