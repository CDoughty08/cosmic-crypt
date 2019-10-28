import { derivePBKDF2Key, derivePBKDF2KeySync } from '../utility/derive-pbkdf2';

import { checkPBKDF2Inputs } from '../lib/pbkdf2/check-inputs';
import { doPBKDF2Encrypt } from '../lib/pbkdf2/encrypt';
import { getPBKDF2Rounds } from '../lib/pbkdf2/get-rounds';

export async function encryptPBKDF2(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds?: number): Promise<Buffer> {
  checkPBKDF2Inputs(password, salt, iv);

  const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
  const keyInfo = await derivePBKDF2Key(password, salt, actualRounds);

  return doPBKDF2Encrypt(buffer, iv, salt, roundsBuffer, keyInfo);
}

export function encryptPBKDF2Sync(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds?: number): Buffer {
  checkPBKDF2Inputs(password, salt, iv);

  const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
  const keyInfo = derivePBKDF2KeySync(password, salt, actualRounds);

  return doPBKDF2Encrypt(buffer, iv, salt, roundsBuffer, keyInfo);
}
