#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';

// import chalk from 'chalk';
import * as inquirer from 'inquirer';

import { version } from '../../package.json';

import * as commander from 'commander';

import { CosmicCrypt } from '../';

// console.log(chalk`Cosmic Crypt v{blue ${version}}`);

// const runState = {
//   mode: 'Encrypt',
//   cipher: 'PBKDF2',
//   pbkdf2Rounds: 10000
// };

// async function entryPrompt() {

//   const initialPrompt = await inquirer.prompt([
//     {
//       choices: ['encrypt', 'decrypt'],
//       message: 'Choose a mode',
//       name: 'mode',
//       type: 'list'
//     },
//     {
//       choices: ['PBKDF2', 'X25519', 'X448'],
//       message: 'Choose cipher type',
//       name: 'cipher',
//       type: 'list'
//     }
//   ]);

//   runState.mode = initialPrompt.mode;
//   runState.cipher = initialPrompt.cipher;

//   if (runState.mode === 'encrypt') {
//     const keyCheckPrompt = await inquirer.prompt([
//       {
//         default: false,
//         message: 'Use an existing key',
//         name: 'existingkey',
//         type: 'confirm'
//       }
//     ]);

//     const existingKey = keyCheckPrompt.existingkey === true;

//     if (existingKey === false) {
//       if (runState.cipher === 'PBKDF2') {
//         const pbkdf2Prompt = await inquirer.prompt([
//           {
//             default: 10000,
//             message: 'Number of rounds',
//             name: 'rounds',
//             type: 'number'
//           }
//         ]);

//         runState.pbkdf2Rounds = pbkdf2Prompt.rounds;
//       }
//     }
//     else {
//       if (runState.cipher === 'PBKDF2') {
//         const useFilePrompt = await inquirer.prompt([
//           {
//             choices: ['Import from key file', 'Provide via cli'],
//             default: 0,
//             message: 'How do you want to provide the key',
//             name: 'keyImportType',
//             type: 'list'
//           }
//         ]);
//       }
//     }
//   }
// }
// entryPrompt();

// cosmic-crypt --enc --type PBKDF2 --keyfile /etc/ssl/ccrypt.pub --text "test content"

const validTypes = new Set(['PBKDF2', 'X25519', 'X448']);

commander
  // tslint:disable-next-line:no-var-requires
  .version(version)
  .option('-e --encrypt', 'encrypt mode')
  .option('-d --decrypt', 'decrypt mode')
  .option('-c --cipher [text]', 'cipher mode PBKDF2, X25519, X448')
  .option('-i --infile [text]', 'Name of the file to encrypt/decrypt')
  .option('-o --outfile [text]', 'Name of the file to output the (de)ciphered content')
  .option('-k --keyfile [text]', 'Name of key file to use')
  .parse(process.argv);

async function processCli() {
  if ((!commander.encrypt && !commander.decrypt) || (commander.encrypt && commander.decrypt)) {
    console.log('Must specify either --encrypt, or --decrypt');
    process.exit(1);
  }

  if (!commander.cipher) {
    console.log('Must specify a valid --cipher');
    process.exit(1);
  }

  if (!validTypes.has(`${commander.cipher}`.toUpperCase())) {
    console.log(`${commander.cipher} is not a valid cipher`);
  }

  const mode = commander.encrypt ? 'encrypt' : 'decrypt';

  try {
    switch (mode) {
      case 'encrypt':
        switch (`${commander.cipher}`.toUpperCase()) {
          case 'PBKDF2': {
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
            break;
          }
          case 'X25519': {

            break;
          }
          case 'X448': {
            break;
          }
        }
        break;
      case 'decrypt':
        if (!fs.existsSync(commander.keyfile)) {
          console.log(`Key file: '${commander.keyfile}' does not exist.`);
          process.exit(1);
        }

        const decrypted = CosmicCrypt.decryptPBKDF2Sync(fs.readFileSync(commander.infile), fs.readFileSync(commander.keyfile));

        fs.writeFileSync(commander.outfile, decrypted);
        console.log(`Decrypted content written to ${commander.outfile}`);
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
