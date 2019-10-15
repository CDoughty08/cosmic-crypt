import * as fs from 'fs';
import * as path from 'path';

import * as commander from 'commander';
import * as inquirer from 'inquirer';

import { CosmicCrypt } from '../cosmic-crypt';

export async function handlePBKDF2CLIEncrypt() {
  const creds = CosmicCrypt.generatePBKDF2CredentialsSync();

  if (!commander.keyfile) {
    // 1: Prompt for where to save the keyfile ( always saved with 400 permissions )
    const keyLocPrompt = await inquirer.prompt({
      type: 'input',
      name: 'keyFileLocation',
      message: 'Where to save the generated key file?',
      default: path.resolve(process.cwd(), 'ccrypt.key')
    });

    let overwrite = true;
    if (fs.existsSync(keyLocPrompt.keyFileLocation)) {
      const overwritePrompt = await inquirer.prompt({
        type: 'confirm',
        message: 'File already exists. Try to overwrite it?',
        name: 'overwrite',
        default: false
      });

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

  const encrypted = CosmicCrypt.encryptPBKDF2Sync(
    fs.readFileSync(commander.infile),
    creds
  );

  fs.writeFileSync(commander.outfile, encrypted);
  console.log(`Encrypted content written to ${commander.outfile}`);
}

export async function handlePBKDF2CLIDecrypt() {
  if (!fs.existsSync(commander.keyfile)) {
    console.log(`Key file: '${commander.keyfile}' does not exist.`);
    process.exit(1);
  }

  const decrypted = CosmicCrypt.decryptPBKDF2Sync(fs.readFileSync(commander.infile), fs.readFileSync(commander.keyfile));

  fs.writeFileSync(commander.outfile, decrypted);
  console.log(`Decrypted content written to ${commander.outfile}`);
}
