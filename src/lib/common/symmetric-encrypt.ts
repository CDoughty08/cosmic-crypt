import * as crypto from 'crypto';

import { HEX_MARKER_BUFFER, HMAC_ALGORITHM, SYMMETRIC_CIPHER } from './constants';
import { SymmetricKDFType } from './types';

type PBKDF2KDF = SymmetricKDFType['PBKDF2'];

export function doSymmetricEncrypt<K extends keyof SymmetricKDFType>(kdf: K, rawData: Buffer, opts: SymmetricKDFType[K]) {
  const cipher = crypto.createCipheriv(SYMMETRIC_CIPHER, opts.keyInfo.derivedKey, opts.iv);
  const hmac = crypto.createHmac(HMAC_ALGORITHM, opts.keyInfo.hmacKey);
  const data = Buffer.concat(
    [
      cipher.update(rawData),
      cipher.final()
    ]
  ).toString('hex');

  // XOR header with salt to mix output
  const header = Buffer.from(
    [
      HEX_MARKER_BUFFER.toString('hex'),
      kdf === 'PBKDF2'
        ? (opts as PBKDF2KDF).rounds.toString('hex')
        : '',
      opts.iv.toString('hex')
    ].join(''),
    'hex'
  );

  for (let i = 0; i < header.byteLength; i++) {
    // tslint:disable-next-line:no-bitwise
    header[i] ^= opts.salt[i % (opts.salt.byteLength - 1)];
  }

  const saltHex = opts.salt.toString('hex');

  hmac.update(header);
  hmac.update(saltHex);
  hmac.update(data);

  const digest = hmac.digest('hex');

  return Buffer.from(
    [
      header.toString('hex'),
      data,
      digest,
      saltHex
    ].join('')
  );
}
