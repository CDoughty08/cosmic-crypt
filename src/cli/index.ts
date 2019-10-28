#!/usr/bin/env node
import { version } from '../../package.json';

import * as commander from 'commander';

import { handlePBKDF2CLI } from './pbkdf2';
import { handleScryptCLI } from './scrypt.js';

import { kdfPrompt, modePrompt, typePrompt } from './prompts';

const validModes = new Set(['symmetric', 'asymmetric']);

commander
  // tslint:disable-next-line:no-var-requires
  .version(version)
  .option('-e --encrypt', 'encrypt mode')
  .option('-d --decrypt', 'decrypt mode')
  .option('-m --mode [text]', 'mode mode symmetric or asymmetric')
  .option('-i --infile [text]', 'Name of the file to encrypt/decrypt')
  .option('-o --outfile [text]', 'Name of the file to output the (de)modeed content')
  .option('-k --keyfile [text]', 'Name of key file to use')
  .parse(process.argv);

async function processCli() {
  if (commander.encrypt && commander.decrypt) {
    console.log(`You must choose either --encrypt or --decrypt`);
    return process.exit(1);
  }

  if (!commander.encrypt && !commander.decrypt) {
    const whichPrompt = await typePrompt();

    commander[whichPrompt.type] = true;
  }

  if (!commander.mode) {
    const whichPrompt = await modePrompt();

    commander.mode = whichPrompt.mode;
  }
  else if (!validModes.has(commander.mode.toLowerCase())) {
    console.log(`'${commander.mode}' is not a valid mode`);
    return process.exit(1);
  }

  commander.mode = commander.mode.toLowerCase();

  const type = commander.encrypt ? 'encrypt' : 'decrypt';

  try {
    switch (`${commander.mode}`.toLowerCase()) {
      case 'symmetric': {
        const whichPrompt = await kdfPrompt();

        if (whichPrompt.kdfType === 'PBKDF2') {
          await handlePBKDF2CLI(type);
        }
        if (whichPrompt.kdfType === 'SCRYPT') {
          await handleScryptCLI(type);
          return process.exit(1);
        }
        break;
      }
      case 'asymmetric': {
        // TODO:
        break;
      }
    }
  }
  catch (e) {
    console.error(e);
    return process.exit(1);
  }
  return process.exit(0);
}

processCli();
