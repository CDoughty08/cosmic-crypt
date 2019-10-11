import { decryptPBKDF2, decryptPBKDF2Sync } from './crypt/decrypt-pbkdf2';
import { encryptPBKDF2, encryptPBKDF2Sync } from './crypt/encrypt-pbkdf2';

import * as utility from './utility';

export class CosmicCrypt {
    /**
     * Generate credentials set using secure random bytes
     *
     * @static
     * @returns {Promise<utility.CryptCredentials>}
     * @memberof CosmicCrypt
     */
    public static async generatePBKDF2Credentials(): Promise<utility.CryptCredentials> {
        const res = await Promise.all([
          utility.randomBytes(utility.PASS_LENGTH),
          utility.randomBytes(utility.IV_LENGTH),
          utility.randomBytes(utility.SALT_LENGTH)
        ]);

        return {
            iv: res[0],
            password: res[1],
            salt: res[2]
        };
    }

    public static generatePBKDF2CredentialsSync(): utility.CryptCredentials {
        return {
            iv: utility.randomBytesSync(utility.IV_LENGTH),
            password: utility.randomBytesSync(utility.PASS_LENGTH),
            salt: utility.randomBytesSync(utility.SALT_LENGTH)
        };
    }

    /**
     * asynchronous encryption
     *
     * @static
     * @param {Buffer} buffer
     * @param {utility.CryptCredentials} credentials
     * @returns {Promise<Buffer>}
     * @memberof CosmicCrypt
     */
    public static async encryptPBKDF2(buffer: Buffer, credentials: utility.CryptCredentials): Promise<Buffer> {
        return encryptPBKDF2(buffer, credentials.password, credentials.iv, credentials.salt);
    }

    /**
     *  synchronous encryption
     *
     * @static
     * @param {Buffer} buffer
     * @param {utility.CryptCredentials} credentials
     * @returns {Buffer}
     * @memberof CosmicCrypt
     */
    public static encryptPBKDF2Sync(buffer: Buffer, credentials: utility.CryptCredentials): Buffer {
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
        return (Buffer.from(buffer.slice(0, utility.MARKER.length * 2).toString(), 'hex').compare(Buffer.from(utility.MARKER)) === 0);
    }
}
