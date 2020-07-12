import {
  EncryptErrorCode,
  IV_LENGTH,
  PASS_LENGTH,
  SALT_LENGTH
} from './constants';

export function checkAsymmetricInputs(password: Buffer, salt: Buffer, iv: Buffer) {
  if (password.length < PASS_LENGTH) {
    throw { code: EncryptErrorCode.PASSWORD_TOO_SHORT, message: `Password must be ${PASS_LENGTH} bytes or more.` };
  }

  if (salt.length !== SALT_LENGTH) {
    throw { code: EncryptErrorCode.SALT_INVALID_LENGTH, message: `Salt must be ${SALT_LENGTH} bytes.` };
  }

  if (iv.length !== IV_LENGTH) {
    throw { code: EncryptErrorCode.IV_INVALID_LENGTH, message: `Initialization Vector must be ${IV_LENGTH} bytes.` };
  }
}
