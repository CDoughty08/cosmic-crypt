import { MARKER, MARKER_BUFFER } from '../../utility/constants';

import {
  EncryptedData,
  IV_LENGTH,
  PBKDF2HeaderSize,
  PBKDF2TrailerSize,
  ROUNDS_SIZE,
  SALT_LENGTH,
  UnpackErrorCode
} from './constants';

export function unpack(buffer: Buffer): EncryptedData {
  const metaLength = PBKDF2HeaderSize + PBKDF2TrailerSize;
  if ( buffer.byteLength < metaLength ) {
    throw { code: UnpackErrorCode.INVALID_META_LENGTH, message: 'Decrypt Error' };
  }

  // Unpack and unmix header
  const saltPosition = buffer.byteLength - SALT_LENGTH * 2;
  const salt = buffer.slice(saltPosition);

  const encoded = Buffer.from(buffer.slice(0, PBKDF2HeaderSize));
  const headerRaw = Buffer.from(encoded.toString(), 'hex');
  const saltRaw = Buffer.from(salt.toString(), 'hex');

  for (let i = 0; i < encoded.byteLength; i++) {
    // tslint:disable-next-line:no-bitwise
    encoded[i] = headerRaw[i] ^ saltRaw[i % (saltRaw.byteLength - 1)];
  }

  const headerDecoded = Buffer.from(encoded.slice(0, PBKDF2HeaderSize / 2).toString('hex'));

  if ( Buffer.from(headerDecoded.slice(0, MARKER.length * 2).toString(), 'hex').compare(MARKER_BUFFER) !== 0 ) {
    throw { code: UnpackErrorCode.MISSING_MARKER, message: 'Decrypt Error' };
  }

  let offset = MARKER.length * 2;
  const rounds = headerDecoded.slice(offset, ROUNDS_SIZE * 2 + offset);

  offset += ROUNDS_SIZE * 2;

  const iv = headerDecoded.slice(offset, IV_LENGTH * 2 + offset);

  offset += IV_LENGTH * 2;

  const encrypted = buffer.slice(offset, buffer.byteLength - PBKDF2TrailerSize);

  const hmac = buffer.slice(buffer.byteLength - PBKDF2TrailerSize, buffer.byteLength - SALT_LENGTH * 2);

  if ( encrypted.length % 32 !== 0 ) {
    throw { code: UnpackErrorCode.INVALID_ENCRYPTED_DATA, message: 'Decrypt Error' };
  }

  return {
    headerRaw,
    encrypted,
    hmac,
    iv,
    rounds,
    salt
  };
}
