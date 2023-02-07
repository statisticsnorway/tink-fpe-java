package no.ssb.crypto.tink.fpe;


import lombok.*;
import no.ssb.crypto.tink.fpe.util.ByteArrayUtil;

/**
 * FpeParams is used as an argument when invoking encrypt and decrypt functions. It allows the user to specify
 * additional details such as how to handle unknown characters, using a custom tweak, etc.
 */
@Getter
@EqualsAndHashCode
public class FpeParams {

    private FpeParams() {}

    /**
     * @return a new FpeParams instance
     */
    public static FpeParams with() {
        return new FpeParams();
    }

    /**
     * The default FpeParams.
     *
     * unknownCharacterStrategy=FAIL, tweak=00000000000000 (56 bits), redactionCharacter=(deduced from FPE alphabet)
     */
    public static final FpeParams DEFAULT = new FpeParams();

    /**
     * unknownCharacterStrategy defines the strategy for how the encryption/decryption process should handle characters
     * that are not in the FPE alphabet.
     */
    private UnknownCharacterStrategy unknownCharacterStrategy = UnknownCharacterStrategy.FAIL;

    /**
     * tweak is used as an additional input to the encryption process that ensures that the same plaintext and key
     * will encrypt to different ciphertexts.
     */
    private byte[] tweak = ByteArrayUtil.hexStringToByteArray("00000000000000");

    /**
     * redactionChar is the character to use for redacting non-alphabet characters. This is only applicable if
     * unknownCharacterStrategy is REDACT.
     *
     * If redactionChar is not defined, a default character will be deduced based on the FPE alphabet.
     */
    private Character redactionChar = null;

    /**
     * unknownCharacterStrategy defines the strategy for how the encryption/decryption process should handle characters
     * that are not in the FPE alphabet.
     */
    public FpeParams unknownCharacterStrategy(@NonNull UnknownCharacterStrategy unknownCharacterStrategy) {
        this.unknownCharacterStrategy = unknownCharacterStrategy;
        return this;
    }

    /**
     * tweak is used as an additional input to the encryption process that ensures that the same plaintext and key
     * will encrypt to different ciphertexts.
     */
    public FpeParams tweak(@NonNull byte[] tweak) {
        // TODO: Validate tweak length
        this.tweak = tweak;
        return this;
    }

    /**
     * redactionChar is the character to use for redacting non-alphabet characters. This is only applicable if
     * unknownCharacterStrategy is REDACT.
     *
     * If redactionChar is not defined, a default character will be deduced based on the FPE alphabet.
     */
    public FpeParams redactionChar(char redactionChar) {
        this.redactionChar = redactionChar;
        return this;
    }

}
