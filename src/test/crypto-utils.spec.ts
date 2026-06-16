import { assert, describe, it } from 'vitest';

import { randomFill } from '../utility';

describe('Crypto Utilities', () => {
  it('randomFill should fill a buffer with random bytes', async () => {
    const buf = Buffer.alloc(16);
    const result = await randomFill(buf);
    assert(Buffer.isBuffer(result), 'result should be a Buffer');
    assert.strictEqual(result.length, 16);
  });

  it('randomFill should accept offset and size', async () => {
    const buf = Buffer.alloc(16);
    const result = await randomFill(buf, 0, 8);
    assert(Buffer.isBuffer(result), 'result should be a Buffer');
    assert.strictEqual(result.length, 16);
  });
});
