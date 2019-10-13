import { decryptPBKDF2, decryptPBKDF2Sync } from './crypt/decrypt-pbkdf2';
import { encryptPBKDF2, encryptPBKDF2Sync } from './crypt/encrypt-pbkdf2';

import { IV_LENGTH, PASS_LENGTH, SALT_LENGTH } from './lib/pbkdf2/constants';
import { CryptCredentials, MARKER } from './utility/constants';
import { randomBytes, randomBytesSync } from './utility/crypto';

export class CosmicCrypt {
    /**
     * Generate credentials set using secure random bytes
     *
     * @static
     * @returns {Promise<CryptCredentials>}
     * @memberof CosmicCrypt
     */
    public static async generatePBKDF2Credentials(): Promise<CryptCredentials> {
        const res = await Promise.all([
          randomBytes(PASS_LENGTH),
          randomBytes(IV_LENGTH),
          randomBytes(SALT_LENGTH)
        ]);

        return {
            iv: res[0],
            password: res[1],
            salt: res[2]
        };
    }

    public static generatePBKDF2CredentialsSync(): CryptCredentials {
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
     * @param {CryptCredentials} credentials
     * @returns {Promise<Buffer>}
     * @memberof CosmicCrypt
     */
    public static async encryptPBKDF2(buffer: Buffer, credentials: CryptCredentials): Promise<Buffer> {
        return encryptPBKDF2(buffer, credentials.password, credentials.iv, credentials.salt);
    }

    /**
     *  synchronous encryption
     *
     * @static
     * @param {Buffer} buffer
     * @param {CryptCredentials} credentials
     * @returns {Buffer}
     * @memberof CosmicCrypt
     */
    public static encryptPBKDF2Sync(buffer: Buffer, credentials: CryptCredentials): Buffer {
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
