import * as path from 'path';

import * as inquirer from 'inquirer';

/**
 * Generic Prompts
 */
export const confirmPrompt =
  (message: string) => inquirer.prompt({
    type: 'confirm',
    message,
    name: 'value',
    default: false
  });

export const keyLocationPrompt =
  () => inquirer.prompt({
    type: 'input',
    name: 'keyFileLocation',
    message: 'Where to save the generated key file?',
    default: path.resolve(process.cwd(), 'ccrypt.key')
  });

export const fileLocationPrompt =
  (message: string, defaultValue?: string) => inquirer.prompt({
    type: 'input',
    name: 'path',
    message,
    default: defaultValue
  });

/**
 * CLI Setup Prompts
 */
export const typePrompt =
  () => inquirer.prompt({
    name: 'type',
    type: 'list',
    choices: ['encrypt', 'decrypt'],
    default: 0,
    message: 'What operation are you performing?'
  });

export const modePrompt =
  () => inquirer.prompt({
    name: 'mode',
    type: 'list',
    choices: ['symmetric', 'asymmetric'],
    default: 0,
    message: 'Which mode to use?'
  });

export const kdfPrompt =
  () => inquirer.prompt({
    name: 'kdfType',
    type: 'list',
    choices: ['PBKDF2', 'SCRYPT'],
    default: 0,
    message: 'Which KDF to use?'
  });
