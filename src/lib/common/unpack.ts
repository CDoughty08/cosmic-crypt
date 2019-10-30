import {
  HEX_MARKER_BUFFER,
  IV_LENGTH,
  MARKER,
  PBKDF2HeaderSize,
  PBKDF2TrailerSize,
  ROUNDS_SIZE,
  SALT_LENGTH,
  ScryptHeaderSize,
  ScryptTrailerSize,
  UnpackErrorCode
} from '../common/constants';
import { EncryptedData } from '../common/types';

export function unpack<K extends keyof EncryptedData>(kdf: K, buffer: Buffer): EncryptedData[K] {
  const headerSize =
    kdf === 'PBKDF2'
      ? PBKDF2HeaderSize
      : ScryptHeaderSize;

  const trailerSize =
    kdf === 'PBKDF2'
      ? PBKDF2TrailerSize
      : ScryptTrailerSize;

  const metaLength = headerSize + trailerSize;

  if (buffer.byteLength < metaLength) {
    throw { code: UnpackErrorCode.INVALID_META_LENGTH, message: 'Decrypt Error' };
  }

  // Unpack and unmix header
  const saltPosition = buffer.byteLength - SALT_LENGTH * 2;
  const salt = buffer.slice(saltPosition);

  const encoded = Buffer.from(buffer.slice(0, headerSize));
  const headerRaw = Buffer.from(encoded.toString(), 'hex');
  const saltRaw = Buffer.from(salt.toString(), 'hex');

  let rounds: Buffer | null = null;

  for (let i = 0; i < encoded.byteLength; i++) {
    // tslint:disable-next-line:no-bitwise
    encoded[i] = headerRaw[i] ^ saltRaw[i % (saltRaw.byteLength - 1)];
  }

  const headerDecoded = Buffer.from(encoded.slice(0, headerSize / 2).toString('hex'));

  if (Buffer.from(headerDecoded.slice(0, MARKER.length * 2).toString(), 'hex').compare(HEX_MARKER_BUFFER) !== 0) {
    throw { code: UnpackErrorCode.MISSING_MARKER, message: 'Decrypt Error' };
  }

  let offset = MARKER.length * 2;

  if (kdf === 'PBKDF2') {
    rounds = headerDecoded.slice(offset, ROUNDS_SIZE * 2 + offset);

    offset += ROUNDS_SIZE * 2;
  }

  const iv = headerDecoded.slice(offset, IV_LENGTH * 2 + offset);

  offset += IV_LENGTH * 2;

  const encrypted = buffer.slice(offset, buffer.byteLength - trailerSize);

  const hmac = buffer.slice(buffer.byteLength - trailerSize, buffer.byteLength - SALT_LENGTH * 2);

  if (encrypted.length % 32 !== 0) {
    throw { code: UnpackErrorCode.INVALID_ENCRYPTED_DATA, message: 'Decrypt Error' };
  }

  if (kdf === 'PBKDF2') {
    return {
      headerRaw,
      encrypted,
      hmac,
      iv,
      rounds,
      salt
    } as EncryptedData[K];
  }
  else {
    return {
      headerRaw,
      encrypted,
      hmac,
      iv,
      salt
    } as EncryptedData[K];
  }
}
