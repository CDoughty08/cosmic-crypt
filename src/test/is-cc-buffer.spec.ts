import { expect } from 'chai';

import {
  CosmicCrypt
} from '..';
import { HEX_MARKER_BUFFER, MARKER, SALT_LENGTH, UnpackErrorCode } from '../lib/common/constants';
import { randomBytes } from '../utility/crypto';

describe('isCosmicCryptBuffer', () => {

  it('should fail with invalid length', () => {
    const buffer = Buffer.from(Array(MARKER.length * 2).fill(0));

    expect(CosmicCrypt.isCosmicCryptBuffer(buffer)).to.equal(UnpackErrorCode.INVALID_META_LENGTH);
  });

  it('should fail if marker does not match', () => {
    const buffer = Buffer.from(Array(MARKER.length * 2 + SALT_LENGTH * 2).fill(0));

    expect(CosmicCrypt.isCosmicCryptBuffer(buffer)).to.equal(UnpackErrorCode.MISSING_MARKER);
  });

  it('should fail if marker is improperly mixed and valid', async () => {
    const salt = await randomBytes(SALT_LENGTH);
    const buf = Buffer.from(HEX_MARKER_BUFFER);

    for (let i = buf.byteLength; i > 0; i--) {
      // tslint:disable-next-line:no-bitwise
      buf[i] ^= salt[i % (salt.byteLength - SALT_LENGTH / 2)];
    }

    const finalBuffer = CosmicCrypt.isCosmicCryptBuffer(
      Buffer.from(buf.toString('hex') + salt.toString('hex'))
    );

    expect(finalBuffer).to.equal(UnpackErrorCode.MISSING_MARKER);
  });

  it('should succeed if marker is properly mixed and valid', async () => {
    const salt = await randomBytes(SALT_LENGTH);
    const buf = Buffer.from(HEX_MARKER_BUFFER);

    for (let i = 0; i < buf.byteLength; i++) {
      // tslint:disable-next-line:no-bitwise
      buf[i] ^= salt[i % (salt.byteLength - 1)];
    }

    const finalBuffer = CosmicCrypt.isCosmicCryptBuffer(
      Buffer.from(buf.toString('hex') + salt.toString('hex'))
    );

    expect(finalBuffer).to.equal(UnpackErrorCode.SUCCESS);
  });
});
