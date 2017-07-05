import { decrypt } from './crypt/decrypt';
import { encrypt } from './crypt/encrypt';

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
     * returns true if buffer starts with CosmicCrypt marker
     * 
     * @static
     * @param {Buffer} buffer
     * @returns {boolean}
     * @memberof CosmicCrypt
     */
    public static isCosmicCryptBuffer(buffer: Buffer): boolean {
        return ( Buffer.from(buffer.slice(0, utility.MARKER.length * 2).toString(), 'hex').compare(Buffer.from(utility.MARKER)) === 0 );
    }
}
