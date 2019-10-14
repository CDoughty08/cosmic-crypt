import * as crypto from 'crypto';

import { DecryptErrorCode } from '../../utility/constants';
import { KeyMetadata } from '../../utility/derive';

import { EncryptedData, HMAC_ALGORITHM, PBKDF2_CIPHER } from './constants';

export function doPBKDF2Decrypt(data: EncryptedData, keyInfo: KeyMetadata) {
  const hmac = crypto.createHmac(HMAC_ALGORITHM, keyInfo.hmacKey);

  hmac.update(data.headerRaw);
  hmac.update(data.salt);
  hmac.update(data.encrypted);

  const digest = Buffer.from(hmac.digest('hex'));

  if (!crypto.timingSafeEqual(data.hmac, digest)) {
    throw {
      code: DecryptErrorCode.AUTHENTICATION_ERROR,
      message: 'Decrypt Authentication Error'
    };
  }

  const cipher = crypto.createDecipheriv(PBKDF2_CIPHER, keyInfo.derivedKey, Buffer.from(data.iv.toString(), 'hex'));

  const deciphered = Buffer.from(
    [
      cipher.update(data.encrypted.toString(), 'hex', 'binary'),
      cipher.final('binary')
    ].join('')
  );

  return deciphered;
}
