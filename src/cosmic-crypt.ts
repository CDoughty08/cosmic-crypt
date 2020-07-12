import { randomBytes, randomBytesSync, ScryptOptions } from './utility/crypto';

import { checkAsymmetricInputs } from './lib/common/check-inputs';
import { HEX_MARKER_BUFFER, IV_LENGTH, PASS_LENGTH, SALT_LENGTH, UnpackErrorCode } from './lib/common/constants';
import { MARKER, Credentials } from './lib/common/constants';
import { deriveSymmetricKey, deriveSymmetricKeySync } from './lib/common/derive-kdf';
import { unpack } from './lib/common/unpack';

import { doSymmetricDecrypt } from './lib/common/symmetric-decrypt';
import { doSymmetricEncrypt } from './lib/common/symmetric-encrypt';
import { getPBKDF2Rounds } from './lib/pbkdf2/get-rounds';

export class CosmicCrypt {
  /**
   * PBKDF2
   */
  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {Promise<Credentials>}
   * @memberof CosmicCrypt
   */
  public static async generatePBKDF2Credentials(): Promise<Credentials> {
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
   * @returns {Credentials}
   * @memberof CosmicCrypt
   */
  public static generatePBKDF2CredentialsSync(): Credentials {
    return {
      iv: randomBytesSync(IV_LENGTH),
      password: randomBytesSync(PASS_LENGTH),
      salt: randomBytesSync(SALT_LENGTH)
    };
  }

  /** */
  /**
   * asynchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {PBKDF2CryptCredentials} credentials
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async encryptPBKDF2(buffer: Buffer, credentials: Credentials, rounds?: number): Promise<Buffer> {
    const { password, salt, iv } = credentials;
    checkAsymmetricInputs(password, salt, iv);

    const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
    const keyInfo = deriveSymmetricKeySync('PBKDF2', password, salt, { rounds: actualRounds });

    return doSymmetricEncrypt('PBKDF2', buffer, { iv, salt, rounds: roundsBuffer, keyInfo });
  }

  /**
   *  synchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Credentials} credentials
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static encryptPBKDF2Sync(buffer: Buffer, credentials: Credentials, rounds?: number): Buffer {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const { actualRounds, roundsBuffer } = getPBKDF2Rounds(rounds);
    const keyInfo = deriveSymmetricKeySync('PBKDF2', password, salt, { rounds: actualRounds });

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

    const keyInfo = await deriveSymmetricKey('PBKDF2', password, Buffer.from(unpacked.salt.toString(), 'hex'), { rounds });

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

    const keyInfo = deriveSymmetricKeySync('PBKDF2', password, Buffer.from(unpacked.salt.toString(), 'hex'), { rounds });

    return doSymmetricDecrypt(unpacked, keyInfo);
  }

  /**
   * SCRYPT
   */

  /**
   * Generate credentials set using secure random bytes
   *
   * @static
   * @returns {Promise<Credentials>}
   * @memberof CosmicCrypt
   */
  public static async  generateScryptCredentials(): Promise<Credentials> {
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
   * @returns {Credentials}
   * @memberof CosmicCrypt
   */
  public static generateScryptCredentialsSync(): Credentials {
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
   * @param {Credentials} credentials
   * @returns {Promise<Buffer>}
   * @memberof CosmicCrypt
   */
  public static async encryptScrypt(buffer: Buffer, credentials: Credentials, opts?: ScryptOptions): Promise<Buffer> {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const keyInfo = await deriveSymmetricKey('SCRYPT', password, salt, opts);

    return doSymmetricEncrypt('SCRYPT', buffer, { iv, salt, keyInfo });
  }

  /**
   *  synchronous encryption
   *
   * @static
   * @param {Buffer} buffer
   * @param {Credentials} credentials
   * @returns {Buffer}
   * @memberof CosmicCrypt
   */
  public static encryptScryptSync(buffer: Buffer, credentials: Credentials, opts?: ScryptOptions): Buffer {
    const { password, salt, iv } = credentials;

    checkAsymmetricInputs(password, salt, iv);

    const keyInfo = deriveSymmetricKeySync('SCRYPT', password, salt, opts);

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
  public static async decryptScrypt(buffer: Buffer, password: Buffer, opts?: ScryptOptions): Promise<Buffer> {
    const unpacked = unpack('SCRYPT', buffer);

    const keyInfo = await deriveSymmetricKey('SCRYPT', password, Buffer.from(unpacked.salt.toString(), 'hex'), opts);

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
  public static decryptScryptSync(buffer: Buffer, password: Buffer, opts?: ScryptOptions): Buffer {
    const unpacked = unpack('SCRYPT', buffer);

    const keyInfo = deriveSymmetricKeySync('SCRYPT', password, Buffer.from(unpacked.salt.toString(), 'hex'), opts);

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
