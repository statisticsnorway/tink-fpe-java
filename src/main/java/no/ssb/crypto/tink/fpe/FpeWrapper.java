// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package no.ssb.crypto.tink.fpe;

import com.google.crypto.tink.CryptoFormat;
import com.google.crypto.tink.PrimitiveSet;
import com.google.crypto.tink.PrimitiveWrapper;
import com.google.crypto.tink.Registry;
import com.google.crypto.tink.internal.MonitoringUtil;
import com.google.crypto.tink.internal.MutableMonitoringRegistry;
import com.google.crypto.tink.monitoring.MonitoringClient;
import com.google.crypto.tink.monitoring.MonitoringKeysetInfo;
import com.google.crypto.tink.subtle.Bytes;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

/**
 * The implementation of {@code PrimitiveWrapper<Fpe>}.
 *
 * <p>The created primitive works with a keyset (rather than a single key). To encrypt a plaintext,
 * it uses the primary key in the keyset, and prepends to the ciphertext a certain prefix associated
 * with the primary key. To decrypt, the primitive uses the prefix of the ciphertext to efficiently
 * select the right key in the set. If the keys associated with the prefix do not work, the
 * primitive tries all keys with {@link com.google.crypto.tink.proto.OutputPrefixType#RAW}.
 */
public class FpeWrapper implements PrimitiveWrapper<Fpe, Fpe> {
  private static final Logger logger = Logger.getLogger(FpeWrapper.class.getName());

  private static class WrappedFpe implements Fpe {
    private final PrimitiveSet<Fpe> primitives;

    private final MonitoringClient.Logger encLogger;
    private final MonitoringClient.Logger decLogger;

    public WrappedFpe(PrimitiveSet<Fpe> primitives) {
      this.primitives = primitives;
      if (primitives.hasAnnotations()) {
        MonitoringClient client = MutableMonitoringRegistry.globalInstance().getMonitoringClient();
        MonitoringKeysetInfo keysetInfo = MonitoringUtil.getMonitoringKeysetInfo(primitives);
        this.encLogger = client.createLogger(keysetInfo, "fpe", "encrypt");
        this.decLogger = client.createLogger(keysetInfo, "fpe", "decrypt");
      } else {
        this.encLogger = MonitoringUtil.DO_NOTHING_LOGGER;
        this.decLogger = MonitoringUtil.DO_NOTHING_LOGGER;
      }
    }

    @Override
    public byte[] encrypt(final byte[] plaintext, final FpeParams params)
        throws GeneralSecurityException {
      try {
        byte[] output =
            Bytes.concat(
                primitives.getPrimary().getIdentifier(),
                primitives
                    .getPrimary()
                    .getPrimitive()
                    .encrypt(plaintext, params));
        encLogger.log(primitives.getPrimary().getKeyId(), plaintext.length);
        return output;
      } catch (GeneralSecurityException e) {
        encLogger.logFailure();
        throw e;
      }
    }

    @Override
    public byte[] decrypt(final byte[] ciphertext, final FpeParams params)
        throws GeneralSecurityException {
      if (ciphertext.length > CryptoFormat.NON_RAW_PREFIX_SIZE) {
        byte[] prefix = Arrays.copyOf(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE);
        byte[] ciphertextNoPrefix =
            Arrays.copyOfRange(ciphertext, CryptoFormat.NON_RAW_PREFIX_SIZE, ciphertext.length);
        List<PrimitiveSet.Entry<Fpe>> entries = primitives.getPrimitive(prefix);
        for (PrimitiveSet.Entry<Fpe> entry : entries) {
          try {
            byte[] output =
                entry.getPrimitive().decrypt(ciphertextNoPrefix, params);
            decLogger.log(entry.getKeyId(), ciphertextNoPrefix.length);
            return output;
          } catch (GeneralSecurityException e) {
            logger.info("ciphertext prefix matches a key, but cannot decrypt: " + e);
            continue;
          }
        }
      }

      // Let's try all RAW keys.
      List<PrimitiveSet.Entry<Fpe>> entries = primitives.getRawPrimitives();
      for (PrimitiveSet.Entry<Fpe> entry : entries) {
        try {
          byte[] output = entry.getPrimitive().decrypt(ciphertext, params);
          decLogger.log(entry.getKeyId(), ciphertext.length);
          return output;
        } catch (GeneralSecurityException e) {
          continue;
        }
      }
      // nothing works.
      decLogger.logFailure();
      throw new GeneralSecurityException("decryption failed");
    }
  }

  FpeWrapper() {}

  @Override
  public Fpe wrap(final PrimitiveSet<Fpe> primitives) {
    return new WrappedFpe(primitives);
  }

  @Override
  public Class<Fpe> getPrimitiveClass() {
    return Fpe.class;
  }

  @Override
  public Class<Fpe> getInputPrimitiveClass() {
    return Fpe.class;
  }

  public static void register() throws GeneralSecurityException {
    Registry.registerPrimitiveWrapper(new FpeWrapper());
  }
}
