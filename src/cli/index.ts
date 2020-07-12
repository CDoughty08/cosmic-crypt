#!/usr/bin/env node
import { version } from '../../package.json';

import * as commander from 'commander';

import { kdfPrompt, typePrompt } from './prompts';
import { handleCLISymmetricDecrypt } from './symmetric-decrypt.js';
import { handleCLISymmetricEncrypt } from './symmetric-encrypt.js';

commander
  // tslint:disable-next-line:no-var-requires
  .version(version)
  .option('-e --encrypt', 'encrypt mode')
  .option('-d --decrypt', 'decrypt mode')
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

  const type = commander.encrypt ? 'encrypt' : 'decrypt';

  try {
    const whichPrompt = await kdfPrompt();

    type === 'encrypt'
      ? await handleCLISymmetricEncrypt(whichPrompt.kdfType)
      : await handleCLISymmetricDecrypt(whichPrompt.kdfType);
  }
  catch (e) {
    console.error(e);
    return process.exit(1);
  }
  return process.exit(0);
}

processCli();
