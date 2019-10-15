#!/usr/bin/env node
import * as inquirer from 'inquirer';

import { version } from '../../package.json';

import * as commander from 'commander';

import { handlePBKDF2CLIDecrypt, handlePBKDF2CLIEncrypt } from './pbkdf2';

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
  if ((!commander.encrypt && !commander.decrypt) || (commander.encrypt && commander.decrypt)) {
    console.log('Must specify either --encrypt, or --decrypt');
    process.exit(1);
  }

  if (!commander.mode) {
    console.log('Must specify a valid --mode');
    process.exit(1);
  }

  const mode = commander.encrypt ? 'encrypt' : 'decrypt';

  try {
    switch (mode) {
      case 'encrypt':
        switch (`${commander.mode}`.toLowerCase()) {
          case 'symmetric': {
            const whichPrompt = await inquirer.prompt({
              name: 'kdf',
              type: 'list',
              choices: ['PBKDF2', 'SCRYPT'],
              default: 0,
              message: 'Which KDF to use?'
            });

            if (whichPrompt.kdf === 'PBKDF2') {
              await handlePBKDF2CLIEncrypt();
            }
            if (whichPrompt.kdf === 'SCRYPT') {
              console.log('Not implemented yet');
              process.exit(1);
              return;
            }
            break;
          }
          case 'asymmetric': {
            // TODO:
            break;
          }
        }
        break;
      case 'decrypt':
        switch (`${commander.mode}`.toLowerCase()) {
          case 'symmetric': {
            const whichPrompt = await inquirer.prompt({
              name: 'kdf',
              type: 'list',
              choices: ['PBKDF2', 'SCRYPT'],
              default: 0,
              message: 'Which KDF to use?'
            });

            if (whichPrompt.kdf === 'PBKDF2') {
              handlePBKDF2CLIDecrypt();
            }
            if (whichPrompt.kdf === 'SCRYPT') {
              console.log('Not implemented yet');
              process.exit(1);
              return;
            }
            break;
          }
          case 'asymmetric': {
            // TODO:
            break;
          }
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

processCli();
