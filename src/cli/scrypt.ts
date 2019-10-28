import * as fs from 'fs';

import * as commander from 'commander';

import { CosmicCrypt } from '../cosmic-crypt';
import { fileOverwritePrompt, keyLocationPrompt } from './prompts';

async function handleSCryptCLIEncrypt() {
  const creds = CosmicCrypt.generateSCryptCredentialsSync();

  if (!commander.keyfile) {
    // 1: Prompt for where to save the keyfile ( always saved with 400 permissions )
    const keyLocPrompt = await keyLocationPrompt();

    let overwrite = true;
    if (fs.existsSync(keyLocPrompt.keyFileLocation)) {
      const overwritePrompt = await fileOverwritePrompt();

      overwrite = overwritePrompt.overwrite;
    }

    if (!overwrite) {
      process.exit(1);
    }

    fs.writeFileSync(keyLocPrompt.keyFileLocation, creds.password, { mode: '400' });
  }
  else {
    if (!fs.existsSync(commander.keyfile)) {
      console.log(`Key file: '${commander.keyfile}' does not exist.`);
      process.exit(1);
    }
    creds.password = fs.readFileSync(commander.keyfile);
  }

  // const encrypted = CosmicCrypt.encryptPBKDF2Sync(
  //   fs.readFileSync(commander.infile),
  //   creds
  // );

  // fs.writeFileSync(commander.outfile, encrypted);
  // console.log(`Encrypted content written to ${commander.outfile}`);
}

async function handleSCryptCLIDecrypt() {
  if (!fs.existsSync(commander.keyfile)) {
    console.log(`Key file: '${commander.keyfile}' does not exist.`);
    process.exit(1);
  }

  // const decrypted = CosmicCrypt.decryptPBKDF2Sync(fs.readFileSync(commander.infile), fs.readFileSync(commander.keyfile));

  // fs.writeFileSync(commander.outfile, decrypted);
  // console.log(`Decrypted content written to ${commander.outfile}`);
}

export async function handleScryptCLI(type: 'encrypt' | 'decrypt') {
  switch (type) {
    case 'encrypt':
      return handleSCryptCLIEncrypt();
    case 'decrypt':
      return handleSCryptCLIDecrypt();
  }
}
