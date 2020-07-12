import * as fs from 'fs';
import * as path from 'path';

import * as commander from 'commander';

import { fileLocationPrompt } from './prompts';

import { CosmicCrypt } from '../cosmic-crypt';

export async function handleCLISymmetricDecrypt(kdf: 'PBKDF2' | 'SCRYPT') {
  let password: Buffer;

  if (!commander.keyfile) {
    const keyLocation = await fileLocationPrompt('Keyfile path:', path.resolve(process.cwd(), 'ccrypt.key'));

    password = fs.readFileSync(path.resolve(keyLocation.path));
  }
  else {
    if (!fs.existsSync(commander.keyfile)) {
      console.log(`Key file: '${commander.keyfile}' does not exist.`);
      process.exit(1);
      return;
    }
    password = fs.readFileSync(path.resolve(commander.keyfile));
  }

  if (!commander.infile) {
    const inFilePrompt = await fileLocationPrompt('In file path:');
    commander.infile = path.resolve(inFilePrompt.path);
  }

  const decrypted =
    kdf === 'PBKDF2'
      ? CosmicCrypt.decryptPBKDF2Sync(
        fs.readFileSync(commander.infile),
        password
      )
      : CosmicCrypt.decryptScryptSync(
        fs.readFileSync(commander.infile),
        password
      );

  if (!commander.outfile) {
    const outFilePrompt = await fileLocationPrompt('Out file path:');
    commander.outfile = path.resolve(outFilePrompt.path);
  }

  fs.writeFileSync(commander.outfile, decrypted);
  console.log(`Decrypted content written to ${commander.outfile}`);
}
