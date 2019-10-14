import * as crypto from 'crypto';

import { MARKER_BUFFER } from '../../utility/constants';
import { KeyMetadata } from '../../utility/derive';

import { HMAC_ALGORITHM, PBKDF2_CIPHER } from './constants';

export function doPBKDF2Encrypt(rawData: Buffer, iv: Buffer, salt: Buffer, rounds: Buffer, keyInfo: KeyMetadata) {
  const ivHex = iv.toString('hex');
  const saltHex = salt.toString('hex');
  const roundsHex = rounds.toString('hex');

  const cipher = crypto.createCipheriv(PBKDF2_CIPHER, keyInfo.derivedKey, iv);
  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);
  const data = Buffer.concat(
    [
      cipher.update(rawData),
      cipher.final()
    ]
  ).toString('hex');

  // XOR header with salt to mix output
  const header = Buffer.from(
    [
      MARKER_BUFFER.toString('hex'),
      roundsHex,
      ivHex
    ].join(''),
    'hex'
  );

  for (let i = 0; i < header.byteLength; i++) {
    // tslint:disable-next-line:no-bitwise
    header[i] ^= salt[i % (salt.byteLength - 1)];
  }

  hmac.update(header);
  hmac.update(saltHex);
  hmac.update(data);

  const digest = hmac.digest('hex');

  return Buffer.from(
    [
      header.toString('hex'),
      saltHex,
      digest,
      data
    ].join('')
  );
}
