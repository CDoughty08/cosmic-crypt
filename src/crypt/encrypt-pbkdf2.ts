import { derivePBKDF2Key, derivePBKDF2KeySync } from '../utility/derive-pbkdf2';

import { checkAsymmetricInputs } from '../lib/common/check-inputs';
import { doSymmetricEncrypt } from '../lib/common/symmetric-encrypt';
import { getPBKDF2Rounds } from '../lib/pbkdf2/get-rounds';

export async function encryptPBKDF2(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds?: number): Promise<Buffer> {
  checkAsymmetricInputs(password, salt, iv);

  const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
  const keyInfo = await derivePBKDF2Key(password, salt, actualRounds);

  return doSymmetricEncrypt('PBKDF2', buffer, { iv, salt, rounds: roundsBuffer, keyInfo });
}

export function encryptPBKDF2Sync(buffer: Buffer, password: Buffer, iv: Buffer, salt: Buffer, rounds?: number): Buffer {
  checkAsymmetricInputs(password, salt, iv);

  const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
  const keyInfo = derivePBKDF2KeySync(password, salt, actualRounds);

  return doSymmetricEncrypt('PBKDF2', buffer, { iv, salt, rounds: roundsBuffer, keyInfo });
}
