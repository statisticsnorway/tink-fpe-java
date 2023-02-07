package no.ssb.crypto.tink.fpe;

import java.security.GeneralSecurityException;

/**
 * Static methods and constants for registering with the {@link com.google.crypto.tink.Registry} all
 * instances of {@link no.ssb.crypto.tink.fpe.Fpe} key types supported.
 *
 * <p>To register all Fpe key types provided in the latest Tink version one can do:
 *
 * <pre>{@code
 * FpeConfig.register();
 * }</pre>
 *
 * <p>For more information on how to obtain and use instances of Fpe, see {@link
 * com.google.crypto.tink.KeysetHandle#getPrimitive}.
 */
public final class FpeConfig {

    /**
     * Tries to register with the {@link com.google.crypto.tink.Registry} all instances of {@link
     * com.google.crypto.tink.Catalogue} needed to handle Fpe key types supported in Tink.
     */
    public static void register() throws GeneralSecurityException {
        FpeWrapper.register();
        FpeFfxKeyManager.register(/* newKeyAllowed = */ true);
    }

    private FpeConfig() {}
}
