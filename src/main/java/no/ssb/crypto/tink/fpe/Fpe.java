package no.ssb.crypto.tink.fpe;

import java.security.GeneralSecurityException;

/**
 * Interface for Format-Preserving Encryption.
 *
 * <p>FPE is a type of encryption family that allows for the encryption of data while preserving the original format
 * and length of the plaintext. This is useful in scenarios where data must be encrypted, but the format of the data
 * must remain unchanged for compatibility with existing systems or processes.</p>
 */
public interface Fpe {

        /**
         * Deterministically encrypt {@code plaintext} with {@code FpeParams}.
         *
         * @param plaintext plaintext to encrypt
         * @param params options that adjust how encryption will be performed.
         * @return resulting ciphertext
         * @throws GeneralSecurityException
         */
        byte[] encrypt(final byte[] plaintext, FpeParams params)
                throws GeneralSecurityException;

        /**
         * Deterministically encrypt {@code plaintext} using default {@code FpeParams}.
         *
         * <p>Raise an error and bail out if encountering non-alphabet characters. Use a 56 bits "null-tweak" and
         * deduce the redaction character automatically from the FPE alphabet (if applicable).</p>
         *
         * @param plaintext plaintext to encrypt
         * @return resulting ciphertext
         * @throws GeneralSecurityException
         */
        default byte[] encrypt(final byte[] plaintext)
                throws GeneralSecurityException {
                return encrypt(plaintext, FpeParams.DEFAULT);
        }

        /**
         * Deterministically decrypt {@code ciphertext} with {@code FpeParams}.
         *
         * @param ciphertext ciphertext to decrypt
         * @param params options that adjust how decryption will be performed. This should usually be the same as the
         *               params used to {@link #encrypt(byte[], FpeParams)}
         * @return resulting plaintext
         * @throws GeneralSecurityException
         */
        byte[] decrypt(final byte[] ciphertext, FpeParams params)
                throws GeneralSecurityException;

        /**
         * Deterministically decrypt {@code ciphertext} using default {@code FpeParams}.
         *
         * @param ciphertext ciphertext to decrypt
         * @return resulting plaintext
         * @throws GeneralSecurityException
         */
        default byte[] decrypt(final byte[] ciphertext)
                throws GeneralSecurityException {
                return decrypt(ciphertext, FpeParams.DEFAULT);
        }

}
