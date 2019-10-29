import { doScryptDecrypt } from '../lib/scrypt/decrypt';
import { unpack } from '../lib/scrypt/unpack';
import { deriveScryptKey, deriveScryptKeySync } from '../utility/derive-scrypt';

export async function decryptScrypt(buffer: Buffer, password: Buffer): Promise<Buffer> {
  const unpacked = unpack(buffer);

  const keyInfo = await deriveScryptKey(password, Buffer.from(unpacked.salt.toString(), 'hex'));

  return doScryptDecrypt(unpacked, keyInfo);
}

export function decryptScryptSync(buffer: Buffer, password: Buffer): Buffer {
  const unpacked = unpack(buffer);

  const keyInfo = deriveScryptKeySync(password, Buffer.from(unpacked.salt.toString(), 'hex'));

  return doScryptDecrypt(unpacked, keyInfo);
}
