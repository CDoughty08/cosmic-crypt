import { decryptPBKDF2, decryptPBKDF2Sync } from './crypt/decrypt-pbkdf2';
import { encryptPBKDF2, encryptPBKDF2Sync } from './crypt/encrypt-pbkdf2';

import { IV_LENGTH, PASS_LENGTH, SALT_LENGTH } from './lib/pbkdf2/constants';
import { MARKER, PBKDF2CryptCredentials, SCryptCredentials } from './utility/constants';
import { randomBytes, randomBytesSync } from './utility/crypto';

export class CosmicCrypt {
  /**
   * PBKDF2
   */
  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {Promise<PBKDF2CryptCredentials>}
   * @memberof CosmicCrypt
   */
  public static async generatePBKDF2Credentials(): Promise<PBKDF2CryptCredentials> {
    const res = await Promise.all([
      randomBytes(PASS_LENGTH),
      randomBytes(IV_LENGTH),
      randomBytes(SALT_LENGTH)
    ]);

    return {
      password: res[0],
      iv: res[1],
      salt: res[2]
    };
  }

  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {PBKDF2CryptCredentials}
   * @memberof CosmicCrypt
   */
  public static generatePBKDF2CredentialsSync(): PBKDF2CryptCredentials {
    return {
      iv: randomBytesSync(IV_LENGTH),
      password: randomBytesSync(PASS_LENGTH),
      salt: randomBytesSync(SALT_LENGTH)
    };
  }

  /**
   * asynchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {PBKDF2CryptCredentials} credentials
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async encryptPBKDF2(buffer: Buffer, credentials: PBKDF2CryptCredentials): Promise<Buffer> {
    return encryptPBKDF2(buffer, credentials.password, credentials.iv, credentials.salt);
  }

  /**
   *  synchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {PBKDF2CryptCredentials} credentials
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static encryptPBKDF2Sync(buffer: Buffer, credentials: PBKDF2CryptCredentials): Buffer {
    return encryptPBKDF2Sync(buffer, credentials.password, credentials.iv, credentials.salt);
  }

  /**
   * asynchronous decryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Buffer} password
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async decryptPBKDF2(buffer: Buffer, password: Buffer): Promise<Buffer> {
    return decryptPBKDF2(buffer, password);
  }

  /**
   * synchronous decryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Buffer} password
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static decryptPBKDF2Sync(buffer: Buffer, password: Buffer): Buffer {
    return decryptPBKDF2Sync(buffer, password);
  }

  /**
   * SCRYPT
   */

  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {Promise<SCryptCredentials>}
   * @memberof CosmicCrypt
   */
  public static async  generateSCryptCredentials(): Promise<SCryptCredentials> {
    const res = await Promise.all([
      randomBytes(PASS_LENGTH),
      randomBytes(SALT_LENGTH)
    ]);

    return {
      password: res[0],
      salt: res[1]
    };
  }

  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {SCryptCredentials}
   * @memberof CosmicCrypt
   */
  public static generateSCryptCredentialsSync(): SCryptCredentials {
    return {
      password: randomBytesSync(PASS_LENGTH),
      salt: randomBytesSync(SALT_LENGTH)
    };
  }

  /**
   * asynchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {SCryptCredentials} credentials
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async encryptSCrypt(_buffer: Buffer, _credentials: SCryptCredentials): Promise<Buffer> {
    // return encryptPBKDF2(buffer, credentials.password, credentials.iv, credentials.salt);
    return Buffer.from('TODO');
  }

  /**
   *  synchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {SCryptCredentials} credentials
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static encryptSCryptSync(_buffer: Buffer, _credentials: SCryptCredentials): Buffer {
    // return encryptPBKDF2Sync(buffer, credentials.password, credentials.iv, credentials.salt);
    return Buffer.from('TODO');
  }

  /**
   * asynchronous decryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Buffer} password
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async decryptSCrypt(_buffer: Buffer, _password: Buffer): Promise<Buffer> {
    // return decryptPBKDF2(buffer, password);
    return Buffer.from('TODO');
  }

  /**
   * synchronous decryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Buffer} password
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static decryptSCryptSync(_buffer: Buffer, _password: Buffer): Buffer {
    // return decryptPBKDF2Sync(buffer, password);
    return Buffer.from('TODO');
  }

  /**
   * returns true if buffer starts with CosmicCrypt marker
   *
   * @static
   * @param {Buffer} buffer
   * @returns {boolean}
   * @memberof CosmicCrypt
   */
  public static isCosmicCryptBuffer(buffer: Buffer): boolean {
    return (Buffer.from(buffer.slice(0, MARKER.length * 2).toString(), 'hex').compare(Buffer.from(MARKER)) === 0);
  }
}
