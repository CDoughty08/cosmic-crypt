import { ScryptOptions } from '../utility/crypto';
import { deriveScryptKey, deriveScryptKeySync } from '../utility/derive-scrypt';

import { checkAsymmetricInputs } from '../lib/common/check-inputs';
import { doScryptEncrypt } from '../lib/scrypt/encrypt';

export async function encryptScrypt(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, opts?: ScryptOptions): Promise<Buffer> {
  checkAsymmetricInputs(password, salt, iv);

  const keyInfo = await deriveScryptKey(password, salt, opts);

  return doScryptEncrypt(buffer, iv, salt, keyInfo);
}

export function encryptScryptSync(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, opts?: ScryptOptions): Buffer {
  checkAsymmetricInputs(password, salt, iv);

  const keyInfo = deriveScryptKeySync(password, salt, opts);

  return doScryptEncrypt(buffer, iv, salt, keyInfo);
}
