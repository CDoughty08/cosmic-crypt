import { deriveKey, deriveKeySync } from '../utility/derive';

import { doPBKDF2Decrypt } from '../lib/pbkdf2/decrypt';
import { unpack } from '../lib/pbkdf2/unpack';

export async function decryptPBKDF2(buffer: Buffer, password: Buffer): Promise<Buffer> {
  const unpacked = unpack(buffer);

  const roundsBuffer = Buffer.from(unpacked.rounds.toString(), 'hex');
  const rounds = roundsBuffer.readInt32LE(0);

  const keyInfo = await deriveKey(password, Buffer.from(unpacked.salt.toString(), 'hex'), rounds);

  return doPBKDF2Decrypt(unpacked, keyInfo);
}

export function decryptPBKDF2Sync(buffer: Buffer, password: Buffer): Buffer {
  const unpacked = unpack(buffer);

  const roundsBuffer = Buffer.from(unpacked.rounds.toString(), 'hex');
  const rounds = roundsBuffer.readInt32LE(0);

  const keyInfo = deriveKeySync(password, Buffer.from(unpacked.salt.toString(), 'hex'), rounds);

  return doPBKDF2Decrypt(unpacked, keyInfo);
}
