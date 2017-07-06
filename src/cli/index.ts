#!/usr/bin/env node
import * as fs from 'fs';

import * as commander from 'commander';
// import * as inquirer from 'inquirer';

import { CosmicCrypt } from '../';

commander
  // tslint:disable-next-line:no-var-requires
  .version(require('../../package.json').version)
  .option('--in [filename]', 'Input from file')
  .option('--out [filename]', 'Output to file')
  .option('--phrase [text]', '64 byte passphrase in hex ( 128 bytes )')
  .option('--enc', 'encrypt mode')
  .option('--dec', 'decrypt mode')
  .option('--text [text]', 'in memory encryption')
  .option('--interactive', 'interactive tool')
  .parse(process.argv);

if (commander.interactive) {
  // TODO:
  console.error('Interactive not implemented');
  process.exit(0);
}

if ((!commander.in && !commander.text) || (commander.in && commander.text)) {
  console.error('Must specify input via --in, or --text');
  process.exit(1);
}

if ((!commander.enc && !commander.dec) || (commander.enc && commander.dec)) {
  console.log('Must specify either --enc, or --dec');
  process.exit(1);
}

if (commander.dec && (!commander.phrase)) {
  console.log('Must specify --phrase with --dec');
  process.exit(1);
}

if (!commander.interactive) {
  // So command is good, mode
  const mode = commander.enc ? 'encrypt' : 'decrypt';
  const data = commander.text ? Buffer.from(commander.text) : fs.readFileSync(commander.in);

  try {
    switch (mode) {
      case 'encrypt':
        const creds = CosmicCrypt.generateCredentialsSync();
        creds.password = commander.phrase ? Buffer.from(commander.phrase) : creds.password;

        const encrypted = CosmicCrypt.encryptSync(data, creds);
        if ( !commander.phrase ) {
          console.log(`Generated password: ${creds.password.toString('hex')}`);
        }
        if ( !commander.out ) {
          console.log(`Data: ${encrypted}`);
        }
        else {
          fs.writeFileSync(commander.out, encrypted);
          console.log(`Encrypted content written to ${commander.out}`);
        }
        break;
      case 'decrypt':
        const decrypted = CosmicCrypt.decryptSync(data, Buffer.from(commander.phrase, 'hex'));

        if ( !commander.out ) {
          console.log(`Data: ${decrypted}`);
        }
        else {
          fs.writeFileSync(commander.out, decrypted);
          console.log(`Decrypted content written to ${commander.out}`);
        }
        break;
    }
  }
  catch (e) {
    console.error(e);
    process.exit(1);
  }
  process.exit(0);
}
