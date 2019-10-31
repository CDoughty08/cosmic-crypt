import { checkAsymmetricInputs } from './lib/common/check-inputs';
import { HEX_MARKER_BUFFER, IV_LENGTH, PASS_LENGTH, SALT_LENGTH, UnpackErrorCode } from './lib/common/constants';
import { MARKER, PBKDF2CryptCredentials, ScryptCredentials } from './lib/common/constants';
import { randomBytes, randomBytesSync, ScryptOptions } from './utility/crypto';
import { deriveScryptKey, deriveScryptKeySync } from './utility/derive-scrypt';

import { doSymmetricDecrypt } from './lib/common/symmetric-decrypt';
import { doSymmetricEncrypt } from './lib/common/symmetric-encrypt';
import { unpack } from './lib/common/unpack';
import { getPBKDF2Rounds } from './lib/pbkdf2/get-rounds';
import { derivePBKDF2Key, derivePBKDF2KeySync } from './utility/derive-pbkdf2';

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
  public static async encryptPBKDF2(buffer: Buffer, credentials: PBKDF2CryptCredentials, rounds?: number): Promise<Buffer> {
    const { password, salt, iv } = credentials;
    checkAsymmetricInputs(password, salt, iv);

    const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
    const keyInfo = derivePBKDF2KeySync(password, salt, actualRounds);

    return doSymmetricEncrypt('PBKDF2', buffer, { iv, salt, rounds: roundsBuffer, keyInfo });
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
  public static encryptPBKDF2Sync(buffer: Buffer, credentials: PBKDF2CryptCredentials, rounds?: number): Buffer {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
    const keyInfo = derivePBKDF2KeySync(password, salt, actualRounds);

    return doSymmetricEncrypt('PBKDF2', buffer, { iv, salt, rounds: roundsBuffer, keyInfo });
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
    const unpacked = unpack('PBKDF2', buffer);

    const roundsBuffer = Buffer.from(unpacked.rounds.toString(), 'hex');
    const rounds = roundsBuffer.readInt32LE(0);

    const keyInfo = await derivePBKDF2Key(password, Buffer.from(unpacked.salt.toString(), 'hex'), rounds);

    return doSymmetricDecrypt(unpacked, keyInfo);
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
    const unpacked = unpack('PBKDF2', buffer);

    const roundsBuffer = Buffer.from(unpacked.rounds.toString(), 'hex');
    const rounds = roundsBuffer.readInt32LE(0);

    const keyInfo = derivePBKDF2KeySync(password, Buffer.from(unpacked.salt.toString(), 'hex'), rounds);

    return doSymmetricDecrypt(unpacked, keyInfo);
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
  public static async encryptScrypt(buffer: Buffer, credentials: ScryptCredentials, opts?: ScryptOptions): Promise<Buffer> {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const keyInfo = await deriveScryptKey(password, salt, opts);

    return doSymmetricEncrypt('SCRYPT', buffer, { iv, salt, keyInfo });
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
  public static encryptScryptSync(buffer: Buffer, credentials: ScryptCredentials, opts?: ScryptOptions): Buffer {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const keyInfo = deriveScryptKeySync(password, salt, opts);

    return doSymmetricEncrypt('SCRYPT', buffer, { iv, salt, keyInfo });
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
    const unpacked = unpack('SCRYPT', buffer);

    const keyInfo = await deriveScryptKey(password, Buffer.from(unpacked.salt.toString(), 'hex'));

    return doSymmetricDecrypt(unpacked, keyInfo);
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
    const unpacked = unpack('SCRYPT', buffer);

    const keyInfo = deriveScryptKeySync(password, Buffer.from(unpacked.salt.toString(), 'hex'));

    return doSymmetricDecrypt(unpacked, keyInfo);
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

    if (Buffer.from(headerDecoded.slice(0, MARKER.length * 2).toString(), 'hex').compare(HEX_MARKER_BUFFER) !== 0) {
      return UnpackErrorCode.MISSING_MARKER;
    }

    return UnpackErrorCode.SUCCESS;
  }
}
