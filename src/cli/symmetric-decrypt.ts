import * as fs from 'fs';

import * as commander from 'commander';

import { CosmicCrypt } from '../cosmic-crypt';

export async function handleCLISymmetricDecrypt(kdf: 'PBKDF2' | 'SCRYPT') {
  if (!fs.existsSync(commander.keyfile)) {
    console.log(`Key file: '${commander.keyfile}' does not exist.`);
    process.exit(1);
  }

  const decrypted =
    kdf === 'PBKDF2'
      ? CosmicCrypt.decryptPBKDF2Sync(
        fs.readFileSync(commander.infile),
        fs.readFileSync(commander.keyfile)
      )
      : CosmicCrypt.decryptScryptSync(
        fs.readFileSync(commander.infile),
        fs.readFileSync(commander.keyfile)
      );

  fs.writeFileSync(commander.outfile, decrypted);
  console.log(`Decrypted content written to ${commander.outfile}`);
}
