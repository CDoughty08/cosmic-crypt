import { doSymmetricDecrypt } from '../lib/common/symmetric-decrypt';
import { unpack } from '../lib/common/unpack';
import { deriveScryptKey, deriveScryptKeySync } from '../utility/derive-scrypt';

export async function decryptScrypt(buffer: Buffer, password: Buffer): Promise<Buffer> {
  const unpacked = unpack('SCRYPT', buffer);

  const keyInfo = await deriveScryptKey(password, Buffer.from(unpacked.salt.toString(), 'hex'));

  return doSymmetricDecrypt(unpacked, keyInfo);
}

export function decryptScryptSync(buffer: Buffer, password: Buffer): Buffer {
  const unpacked = unpack('SCRYPT', buffer);

  const keyInfo = deriveScryptKeySync(password, Buffer.from(unpacked.salt.toString(), 'hex'));

  return doSymmetricDecrypt(unpacked, keyInfo);
}
