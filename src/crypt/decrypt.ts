import * as crypto from 'crypto';

import {
  deriveKey,
  ENCRYPT_ALGORITHM,
  HMAC_ALGORITHM,
  unpack
} from '../utility';

export async function decrypt(buffer: Buffer, password: Buffer): Promise<Buffer> {
  const data = unpack(buffer);

  const keyInfo = await deriveKey(password, Buffer.from(data.salt.toString(), 'hex'));

  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);

  hmac.update(data.encrypted);
  hmac.update(data.iv);
  hmac.update(data.salt);

  const digest = Buffer.from(hmac.digest('hex'));

  if ( !crypto.timingSafeEqual(data.hmac, digest) ) {
    throw new Error('Decrypt Authentication Error');
  }

  const cipher = crypto.createDecipheriv(ENCRYPT_ALGORITHM, keyInfo.derivedKey, Buffer.from(data.iv.toString(), 'hex'));

  const deciphered = Buffer.from([
    cipher.update(data.encrypted.toString(), 'hex', 'utf8'),
    cipher.final('utf8')
  ].join(''));

  return deciphered;
}
