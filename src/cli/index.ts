#!/usr/bin/env node
import * as fs from 'fs';
import { Command } from 'commander';
import pkg from '../../package.json';

import { CosmicCrypt } from '../index';

const { version } = pkg;
const program = new Command();

program
  .version(version)
  .option('--in <filename>', 'Input from file')
  .option('--out <filename>', 'Output to file')
  .option('--phrase <text>', '64 byte passphrase in hex ( 128 bytes )')
  .option('--enc', 'encrypt mode')
  .option('--dec', 'decrypt mode')
  .option('--text <text>', 'in memory encryption')
  .option('--interactive', 'interactive tool')
  .parse(process.argv);

const opts = program.opts<{
  in?: string;
  out?: string;
  phrase?: string;
  enc?: boolean;
  dec?: boolean;
  text?: string;
  interactive?: boolean;
}>();

if (opts.interactive) {
  console.error('Interactive not implemented');
  process.exit(0);
}

if ((!opts.in && !opts.text) || (opts.in && opts.text)) {
  console.error('Must specify input via --in, or --text');
  process.exit(1);
}

if ((!opts.enc && !opts.dec) || (opts.enc && opts.dec)) {
  console.error('Must specify either --enc, or --dec');
  process.exit(1);
}

if (opts.dec && !opts.phrase) {
  console.error('Must specify --phrase with --dec');
  process.exit(1);
}

const mode = opts.enc ? 'encrypt' : 'decrypt';
const data = opts.text ? Buffer.from(opts.text) : fs.readFileSync(opts.in!);

try {
  switch (mode) {
    case 'encrypt': {
      const creds = CosmicCrypt.generateCredentialsSync();
      creds.password = opts.phrase ? Buffer.from(opts.phrase, 'hex') : creds.password;
      const encrypted = CosmicCrypt.encryptSync(data, creds);
      if (!opts.phrase) {
        console.log(`Generated password: ${creds.password.toString('hex')}`);
      }
      if (!opts.out) {
        console.log(`Data: ${encrypted}`);
      } else {
        fs.writeFileSync(opts.out, encrypted);
        console.log(`Encrypted content written to ${opts.out}`);
      }
      break;
    }
    case 'decrypt': {
      const decrypted = CosmicCrypt.decryptSync(data, Buffer.from(opts.phrase!, 'hex'));
      if (!opts.out) {
        console.log(`Data: ${decrypted}`);
      } else {
        fs.writeFileSync(opts.out, decrypted);
        console.log(`Decrypted content written to ${opts.out}`);
      }
      break;
    }
  }
} catch (e) {
  console.error(e);
  process.exit(1);
}
process.exit(0);
