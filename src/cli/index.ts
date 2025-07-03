#!/usr/bin/env node
import * as fs from 'fs';
import { Command } from 'commander';
// import * as inquirer from 'inquirer';

import { CosmicCrypt } from '../';

const program = new Command();

program
  .version(require('../../package.json').version)
  .option('--in [filename]', 'Input from file')
  .option('--out [filename]', 'Output to file')
  .option('--phrase [text]', '64 byte passphrase in hex ( 128 bytes )')
  .option('--enc', 'encrypt mode')
  .option('--dec', 'decrypt mode')
  .option('--text [text]', 'in memory encryption')
  .option('--interactive', 'interactive tool')
  .parse(process.argv);

const options = program.opts();

if (options.interactive) {
  // TODO:
  console.error('Interactive not implemented');
  process.exit(0);
}

if ((!options.in && !options.text) || (options.in && options.text)) {
  console.error('Must specify input via --in, or --text');
  process.exit(1);
}

if ((!options.enc && !options.dec) || (options.enc && options.dec)) {
  console.log('Must specify either --enc, or --dec');
  process.exit(1);
}

if (options.dec && (!options.phrase)) {
  console.log('Must specify --phrase with --dec');
  process.exit(1);
}

if (!options.interactive) {
  // So command is good, mode
  const mode = options.enc ? 'encrypt' : 'decrypt';
  const data = options.text ? Buffer.from(options.text) : fs.readFileSync(options.in);

  try {
    switch (mode) {
      case 'encrypt':
        const creds = CosmicCrypt.generateCredentialsSync();
        creds.password = options.phrase ? Buffer.from(options.phrase, 'hex') : creds.password;
        const encrypted = CosmicCrypt.encryptSync(data, creds);
        if ( !options.phrase ) {
          console.log(`Generated password: ${creds.password.toString('hex')}`);
        }
        if ( !options.out ) {
          console.log(`Data: ${encrypted}`);
        }
        else {
          fs.writeFileSync(options.out, encrypted);
          console.log(`Encrypted content written to ${options.out}`);
        }
        break;
      case 'decrypt':
        const decrypted = CosmicCrypt.decryptSync(data, Buffer.from(options.phrase, 'hex'));

        if ( !options.out ) {
          console.log(`Data: ${decrypted}`);
        }
        else {
          fs.writeFileSync(options.out, decrypted);
          console.log(`Decrypted content written to ${options.out}`);
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
