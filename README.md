[![Coverage Status](https://coveralls.io/repos/github/CDoughty08/cosmic-crypt/badge.svg?branch=master)](https://coveralls.io/github/CDoughty08/cosmic-crypt?branch=master)
[![Build Status](https://travis-ci.org/CDoughty08/cosmic-crypt.svg?branch=master)](https://travis-ci.org/CDoughty08/cosmic-crypt)
[![npm version](https://badge.fury.io/js/cosmic-crypt.svg)](https://badge.fury.io/js/cosmic-crypt)

Installation
============
```
npm install cosmic-crypt
```

Anytime the version of of this package changes the HMAC signatures will be invalid when decrypting. Either lock the version to what you need, or re-encrypt you content with the new version, when upgrading.

Quickstart
==============

Usage is extremely simple:
```ts
import { CosmicCrypt } from './cosmic-crypt';

async function sample() {
    const credentials = await CosmicCrypt.generatePBKDF2Credentials();

    const plainText = Buffer.from('Some sample data');

    const sampleEncrypted = await CosmicCrypt.encryptPBKDF2(plainText, credentials);

    const sampleDecrypted = await CosmicCrypt.decryptPBKDF2(sampleEncrypted, credentials.password);

    console.log(`${sampleEncrypted.toString()}`);
    console.log(`${plainText.toString()} === ${sampleDecrypted.toString()}`);
}

sample();
```

Expectations
============
This utility makes a few assumptions about what you want to do, as it was made for a simple purpose. It currently does not provide a large feature set.

Cipher text is encrypted and return as `hex`

The cipher algorithm is currently locked to `aes-256-cbc`

The IV must be 128 bit, 16 bytes.

Passwords must be 64 bytes or larger.

The Salt must be 32 bytes.

pbkdf2 iterations defaults to 10000.

Supplied Error Codes
====================
```ts
enum EncryptErrorCode {
  PASSWORD_TOO_SHORT,
  IV_INVALID_LENGTH,
  SALT_INVALID_LENGTH
}

enum DecryptErrorCode {
  AUTHENTICATION_ERROR
}

// Unpack is part of the decrypt process
enum UnpackErrorCode {
  INVALID_META_LENGTH,
  INVALID_ENCRYPTED_DATA
}
```