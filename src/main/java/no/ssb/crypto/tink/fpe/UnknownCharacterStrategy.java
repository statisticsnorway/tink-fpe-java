package no.ssb.crypto.tink.fpe;

/**
 * UnknownCharacterStrategy defines the strategy for how the encryption/decryption process should handle characters
 * that are not in the FPE alphabet.
 *
 * <p>The underlying FPE algorithm restricts the type of plaintext characters that can be encrypted. Only characters
 * defined in the defined alphabet can be used. Encountering non-alphabet characters can be handled in
 * different ways.</p>
 */
public enum UnknownCharacterStrategy {

    /**
     * Raise an error and bail out if encountering a non-alphabet character.
     */
    FAIL,

    /**
     * Ignore non-alphabet characters, leaving them unencrypted (nested into the ciphertext).
     */
    SKIP,

    /**
     * Before processing the plaintext, replace any characters that are not part of the alphabet with an
     * alphabet-compliant character. Warning: Using this strategy means that decryption may not result in the exact
     * same plaintext being restored.
     */
    REDACT,

    /**
     * Remove all characters that are not part of the alphabet prior to processing. Warning: Using this strategy
     * implies that the length of the plaintext and ciphertext may differ. Furthermore, decryption may not
     * result in the exact same plaintext being restored.
     */
    DELETE

}
