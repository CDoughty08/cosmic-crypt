// import { encrypt } from './crypt/encrypt';

// import { decrypt } from './crypt/decrypt';

export { encrypt, EncryptErrorCode } from './crypt/encrypt';
export { decrypt } from './crypt/decrypt';

// const text = Buffer.from('Test Data!Test Data!Test Data!Test Data!Test Data!Test Data!Test Data!');
// const password = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ12');
// const iv = Buffer.from('1234123412341234');
// const salt = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ123456');

// async function test() {
//   const encrypted = await encrypt(text, password, iv, salt);

//   // const decrypted = await decrypt(encrypted, password);
//   console.log(encrypted.toString());
// }

// test();
