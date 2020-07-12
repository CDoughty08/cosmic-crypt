import { KeyMetadata } from './constants';

export interface SymmetricKDFType {
  PBKDF2: {
    iv: Buffer;
    salt: Buffer;
    rounds: Buffer;
    keyInfo: KeyMetadata;
  };
  SCRYPT: {
    iv: Buffer;
    salt: Buffer;
    keyInfo: KeyMetadata;
  };
}

export interface EncryptedData {
  PBKDF2: {
    headerRaw: Buffer;
    encrypted: Buffer;
    iv: Buffer;
    hmac: Buffer;
    salt: Buffer;
    rounds: Buffer;
  };
  SCRYPT: {
    headerRaw: Buffer;
    encrypted: Buffer;
    iv: Buffer;
    hmac: Buffer;
    salt: Buffer;
  };
}
