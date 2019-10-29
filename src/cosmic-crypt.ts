import { decryptPBKDF2, decryptPBKDF2Sync } from './crypt/decrypt-pbkdf2';
import { encryptPBKDF2, encryptPBKDF2Sync } from './crypt/encrypt-pbkdf2';

import { MARKER_BUFFER, SALT_LENGTH, UnpackErrorCode } from './lib/common/constants';
import { MARKER, PBKDF2CryptCredentials, ScryptCredentials } from './lib/common/constants';
import { IV_LENGTH, PASS_LENGTH } from './lib/pbkdf2/constants';
import { randomBytes, randomBytesSync } from './utility/crypto';

import { decryptScrypt, decryptScryptSync } from './crypt/decrypt-scrypt';
import { encryptScrypt, encryptScryptSync } from './crypt/encrypt-scrypt';

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
   * @returns {Promise<ScryptCredentials>}
   * @memberof CosmicCrypt
   */
  public static async  generateScryptCredentials(): Promise<ScryptCredentials> {
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
   * @returns {ScryptCredentials}
   * @memberof CosmicCrypt
   */
  public static generateScryptCredentialsSync(): ScryptCredentials {
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
   * @param {ScryptCredentials} credentials
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async encryptScrypt(buffer: Buffer, credentials: ScryptCredentials): Promise<Buffer> {
    return encryptScrypt(buffer, credentials.password, credentials.iv, credentials.salt);
  }

  /**
   *  synchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {ScryptCredentials} credentials
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static encryptScryptSync(buffer: Buffer, credentials: ScryptCredentials): Buffer {
    return encryptScryptSync(buffer, credentials.password, credentials.iv, credentials.salt);
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
  public static async decryptScrypt(buffer: Buffer, password: Buffer): Promise<Buffer> {
    return decryptScrypt(buffer, password);
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
  public static decryptScryptSync(buffer: Buffer, password: Buffer): Buffer {
    return decryptScryptSync(buffer, password);
  }

  /**
   * returns true if buffer starts with CosmicCrypt marker
   *
   * @static
   * @param {Buffer} buffer
   * @returns {boolean}
   * @memberof CosmicCrypt
   */
  public static isCosmicCryptBuffer(buffer: Buffer): UnpackErrorCode {
    if (buffer.byteLength < (MARKER.length * 2) + (SALT_LENGTH * 2)) {
      return UnpackErrorCode.INVALID_META_LENGTH;
    }
    // Unpack and unmix header
    const saltPosition = buffer.byteLength - SALT_LENGTH * 2;
    const salt = buffer.slice(saltPosition);

    const encoded = Buffer.from(buffer.slice(0, MARKER.length * 2));
    const headerRaw = Buffer.from(encoded.toString(), 'hex');
    const saltRaw = Buffer.from(salt.toString(), 'hex');

    for (let i = 0; i < encoded.byteLength; i++) {
      // tslint:disable-next-line:no-bitwise
      encoded[i] = headerRaw[i] ^ saltRaw[i % (saltRaw.byteLength - 1)];
    }

    const headerDecoded = Buffer.from(encoded.slice(0, (MARKER.length * 2) / 2).toString('hex'));

    if (Buffer.from(headerDecoded.slice(0, MARKER.length * 2).toString(), 'hex').compare(MARKER_BUFFER) !== 0) {
      return UnpackErrorCode.MISSING_MARKER;
    }

    return UnpackErrorCode.SUCCESS;
  }
}
