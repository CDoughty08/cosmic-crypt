import { PBKDF2_ROUNDS, ROUNDS_SIZE } from './constants';

export function getPBKDF2Rounds(rounds?: number) {
  const actualRounds = rounds || PBKDF2_ROUNDS;

  const roundsBuffer = Buffer.alloc(ROUNDS_SIZE);
  roundsBuffer.writeUInt32LE(actualRounds, 0);

  return {
    actualRounds,
    roundsBuffer
  };
}
