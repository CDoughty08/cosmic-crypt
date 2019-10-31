import * as fs from 'fs';
import * as path from 'path';

import * as commander from 'commander';

import { CosmicCrypt } from '../cosmic-crypt';
import { confirmPrompt, fileLocationPrompt, keyLocationPrompt } from './prompts';

export async function handleCLISymmetricEncrypt(kdf: 'PBKDF2' | 'SCRYPT') {
  const creds =
    kdf === 'PBKDF2'
      ? CosmicCrypt.generatePBKDF2CredentialsSync()
      : CosmicCrypt.generateScryptCredentialsSync();

  if (!commander.keyfile) {
    // 1: Do you want to load an existing file
    const loadExistingPrompt = await confirmPrompt('Load an existing keyfile?');

    if (loadExistingPrompt.value) {
      const keyLocation = await fileLocationPrompt('Keyfile path:', path.resolve(process.cwd(), 'ccrypt.key'));

      commander.keyfile = keyLocation.path;
    }
    else {
      // 2: Prompt for where to save the keyfile ( always saved with 600 permissions )
      const keyLocPrompt = await keyLocationPrompt();

      let overwrite = true;
      if (fs.existsSync(keyLocPrompt.keyFileLocation)) {
        const overwritePrompt = await confirmPrompt('File already exists. Try to overwrite it?');

        overwrite = overwritePrompt.value;
      }

      if (!overwrite) {
        const loadExistingPrompt2 = await confirmPrompt('Do you want to load the existing key?');
        if (loadExistingPrompt2.value) {
          creds.password = fs.readFileSync(keyLocPrompt.keyFileLocation);
        }
        else {
          process.exit(1);
        }
      }
      else {
        fs.writeFileSync(keyLocPrompt.keyFileLocation, creds.password, { mode: '600' });
      }
    }
  }
  else {
    if (!fs.existsSync(commander.keyfile)) {
      console.log(`Key file: '${commander.keyfile}' does not exist.`);
      process.exit(1);
    }
    creds.password = fs.readFileSync(commander.keyfile);
  }

  if (!commander.infile) {
    const inFilePrompt = await fileLocationPrompt('In file path:');
    commander.infile = path.resolve(inFilePrompt.path);
  }

  const encrypted =
    kdf === 'PBKDF2'
      ? CosmicCrypt.encryptPBKDF2Sync(
        fs.readFileSync(commander.infile),
        creds
      )
      : CosmicCrypt.encryptScryptSync(
        fs.readFileSync(commander.infile),
        creds
      );

  if (!commander.outfile) {
    const outFilePrompt = await fileLocationPrompt('Out file path:');
    commander.outfile = path.resolve(outFilePrompt.path);
  }

  fs.writeFileSync(commander.outfile, encrypted);
  console.log(`Encrypted content written to ${commander.outfile}`);
}
