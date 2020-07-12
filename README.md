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

Data layouts
==============

Symmetric Encryption:

Shows data layout by

KDF  
[byte alignment]  
[data type]

```ts
PBKDF2
[   0  - 11   ][   12 - 19   ][       20 - 83       ][    84 - N    ][(Len - 192) - (Len - 64)][(Len - 64) - EOF]
[CCRYPT Marker][PBKDF2 Rounds][Initialization Vector][Encrypted Data][     HMAC Signature     ][      SALT      ]
```


```ts
SCRYPT
[   0  - 11   ][       16 - 79       ][    80 - N    ][(Len - 192) - (Len - 64)][(Len - 64) - EOF]
[CCRYPT Marker][Initialization Vector][Encrypted Data][     HMAC Signature     ][      SALT      ]
```

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