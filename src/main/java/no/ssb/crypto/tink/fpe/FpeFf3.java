package no.ssb.crypto.tink.fpe;

import com.google.common.base.CharMatcher;
import com.privacylogistics.FF3Cipher;
import no.ssb.crypto.tink.fpe.text.CharacterSkipper;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;

import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.*;


// TODO: Validate/restrict tweak lengths for user provided tweaks?

/**
 * Fpe primitive for the FF3-1 mode of Format-Preserving Encryption.
 */
public final class FpeFf3 implements Fpe {

    /**
     * MIN_CHUNK_SIZE is the min number of characters for each plaintext fragment being encrypted.
     *
     * <p>The underlying FF3-1 implementation has limitations for minimum plaintext length.
     * If the supplied plaintext is shorter than a certain length (MIN_CHUNK_SIZE), the plaintext
     * cannot be encrypted.</p>
     */
    private static final int MIN_CHUNK_SIZE = 4;

    /**
     * MAX_CHUNK_SIZE is the max number of characters for each plaintext fragment being encrypted.
     *
     * <p>The underlying FF3-1 implementation has limitations for maximum plaintext length (depending on alphabet radix).
     * If the supplied plaintext exceeds a certain length (MAX_CHUNK_SIZE), it is divided into chunks before being processed.</p>
     *
     * <p>For more information, refer to: https://github.com/mysto/java-fpe#usage</p>
     * */
    private static final int MAX_CHUNK_SIZE = 30;

    /**
     * NULL_HEX_TWEAK is hexadecimal string representation of the default tweak. It is used if a tweak is not explicitly
     * specified by the user.
     *
     * <p>The tweak is a value used as an additional input to the encryption process. A tweak ensures that the same
     * plaintext and key will encrypt to different ciphertexts.</p>
     *
     * <p>The size of the tweak is usually recommended to be 128 bits (16 characters string) to provide sufficient
     * randomness and security. However, the underlying FF3-1 implementation (Mysto FPE (python)) enforces either
     * 56 or 64 bits tweak lengths (a 7 or 8 characters string). Thus, for compatibility reasons, this is also
     * enforced here.
     * </p>
     */
    private static final String NULL_HEX_TWEAK = "00000000000000"; // 56 bits

    /**
     * The supported key sizes - either 128, 192 or 256 bits (16, 24 or 32 chars)
     */
    private static final Collection<Integer> SUPPORTED_KEY_SIZES = Arrays.asList(128, 192, 256);

    /**
     * alphabet is a string of possible characters or symbols used to represent the data being encrypted.
     *
     * <p>The alphabet typically consists of a limited number of characters such as letters, numbers, and special
     * characters. The size and composition of the alphabet determine the number of possible combinations of characters
     * that can be used to encrypt the data, which affects the level of security provided by the encryption process.</p>
     */
    private final String alphabet;

    /**
     * defaultRedactionChar is the precalculated char to use for redacting non-alphabet characters. This is only
     * applicable if unknownCharacterStrategy is REDACT.
     */
    private final char defaultRedactionChar;

    /**
     * ff3 contains the underlying FF3-1 algorithm implementation provided by https://github.com/mysto/java-fpe
     */
    private final FF3Cipher ff3;

    FpeFf3(final byte[] key, String alphabet) throws GeneralSecurityException {
        if (!SUPPORTED_KEY_SIZES.contains(key.length * 8)) {
            throw new InvalidKeyException("invalid key size: " + (key.length * 8) + " bits");
        }

        this.alphabet = alphabet;
        this.defaultRedactionChar = redactionCharOf(alphabet);
        this.ff3 = new FF3Cipher(byteArrayToHexString(key), NULL_HEX_TWEAK, alphabet);
    }

    /**
     * Deterministically encrypt {@code plaintext} with {@code FpeParams} using FF3-1 mode.
     *
     * @param plaintext plaintext to encrypt
     * @param params options that adjust how encryption will be performed.
     * @return resulting ciphertext
     * @throws GeneralSecurityException
     */
    @Override
    public byte[] encrypt(final byte[] plaintext, final FpeParams params)
            throws GeneralSecurityException {
        if (plaintext == null || plaintext.length == 0) {
            return new byte[0];
        }

        String tweak = hexTweakOf(params.getTweak());
        String pt = b2s(plaintext);

        CharacterSkipper charSkipper = null;
        if (params.getUnknownCharacterStrategy() == UnknownCharacterStrategy.SKIP) {
            charSkipper = new CharacterSkipper(pt, alphabet);
            pt = charSkipper.getProcessedText();
        }
        else if (params.getUnknownCharacterStrategy() == UnknownCharacterStrategy.DELETE) {
            pt = CharMatcher.anyOf(alphabet).retainFrom(pt);
        }
        else if (params.getUnknownCharacterStrategy() == UnknownCharacterStrategy.REDACT) {
            pt = CharMatcher.noneOf(alphabet).replaceFrom(pt, Optional.ofNullable(params.getRedactionChar()).orElse(defaultRedactionChar));
        }
        else if (params.getUnknownCharacterStrategy() == UnknownCharacterStrategy.FAIL) {
            if (! CharMatcher.anyOf(alphabet).matchesAllOf(pt)) {
                throw new IncompatiblePlaintextException("Plaintext can only contain characters from the alphabet '" + alphabet + "'");
            }
        }

        // TODO: Optimize and protect - use byte[] instead of String?
        StringBuilder ciphertext = new StringBuilder();
        for (int pos=0, chunkNo=1; pos<pt.length(); pos+=MAX_CHUNK_SIZE, chunkNo++) {
            String chunk = pt.substring(pos, Math.min(chunkNo*MAX_CHUNK_SIZE, pt.length()));
            ciphertext.append(chunk.length() < MIN_CHUNK_SIZE
                    ? chunk
                    : ff3.encrypt(chunk, tweak));
        }

        if (charSkipper != null && charSkipper.hasSkipped()) {
            charSkipper.injectSkippedInto(ciphertext);
        }

        return s2b(ciphertext.toString());
    }

    /**
     * Deterministically decrypt {@code ciphertext} with {@code FpeParams} using FF3-1 mode.
     *
     * @param ciphertext ciphertext to decrypt
     * @param params options that adjust how decryption will be performed. This should usually be the same as the
     *               params used to {@link #encrypt(byte[], FpeParams)}
     * @return resulting plaintext
     * @throws GeneralSecurityException
     */
    @Override
    public byte[] decrypt(final byte[] ciphertext, final FpeParams params)
            throws GeneralSecurityException {
        if (ciphertext == null || ciphertext.length == 0) {
            return new byte[0];
        }

        String tweak = hexTweakOf(params.getTweak());
        String ct = b2s(ciphertext);
        CharacterSkipper charSkipper = null;

        if (params.getUnknownCharacterStrategy() == UnknownCharacterStrategy.SKIP) {
            charSkipper = new CharacterSkipper(ct, alphabet);
            ct = charSkipper.getProcessedText();
        }

        StringBuilder plaintext = new StringBuilder();
        for (int pos=0, chunkNo=1; pos<ct.length(); pos+=MAX_CHUNK_SIZE, chunkNo++) {
            String chunk = ct.substring(pos, Math.min(chunkNo*MAX_CHUNK_SIZE, ct.length()));
            plaintext.append(chunk.length() < MIN_CHUNK_SIZE
                    ? chunk
                    : ff3.decrypt(chunk, tweak));
        }

        if (charSkipper != null && charSkipper.hasSkipped()) {
            charSkipper.injectSkippedInto(plaintext);
        }

        return s2b(plaintext.toString());
    }

    // TODO: Unit test
    static char redactionCharOf(String alphabet) {
        for (char c : "*?_-Xx0".toCharArray()) {
            if (alphabet.indexOf(c) != -1) {
                return c;
            }
        }

        throw new IllegalStateException("Unable to deduce redaction character for alphabet '" + alphabet + "'");
    }

    // TODO: Validate bitsize of tweak
    private String hexTweakOf(byte[] bArr) {
        return (bArr == null || bArr.length == 0)
                ? NULL_HEX_TWEAK
                : byteArrayToHexString(bArr);
    }

}
