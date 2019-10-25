import * as inquirer from 'inquirer';

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
