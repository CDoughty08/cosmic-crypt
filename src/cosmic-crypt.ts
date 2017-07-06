import { decrypt, decryptSync } from './crypt/decrypt';
import { encrypt, encryptSync } from './crypt/encrypt';

import * as utility from './utility';

export class CosmicCrypt {
    /**
     * Generate credentials set using secure random bytes
     *
     * @static
     * @returns {Promise<utility.CryptCredentials>}
     * @memberof CosmicCrypt
     */
    public static async generateCredentials(): Promise<utility.CryptCredentials> {
        return {
            iv: await utility.randomBytes(utility.IV_LENGTH),
            password: await utility.randomBytes(utility.PASS_LENGTH),
            salt: await utility.randomBytes(utility.SALT_LENGTH)
        };
    }

    public static generateCredentialsSync(): utility.CryptCredentials {
        return {
            iv: utility.randomBytesSync(utility.IV_LENGTH),
            password: utility.randomBytesSync(utility.PASS_LENGTH),
            salt: utility.randomBytesSync(utility.SALT_LENGTH)
        };
    }
    /**
     * Promise based asynchronous encryption
     *
     * @static
     * @param {Buffer} buffer
     * @param {utility.CryptCredentials} credentials
     * @returns {Promise<Buffer>}
     * @memberof CosmicCrypt
     */
    public static async encrypt(buffer: Buffer, credentials: utility.CryptCredentials): Promise<Buffer> {
        return await encrypt(buffer, credentials.password, credentials.iv, credentials.salt);
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
    public static encryptSync(buffer: Buffer, credentials: utility.CryptCredentials): Buffer {
        return encryptSync(buffer, credentials.password, credentials.iv, credentials.salt);
    }

    /**
     * Promise based asynchronous decryption
     *
     * @static
     * @param {Buffer} buffer
     * @param {Buffer} password
     * @returns {Promise<Buffer>}
     * @memberof CosmicCrypt
     */
    public static async decrypt(buffer: Buffer, password: Buffer): Promise<Buffer> {
        return await decrypt(buffer, password);
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
    public static decryptSync(buffer: Buffer, password: Buffer): Buffer {
        return decryptSync(buffer, password);
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
