package no.ssb.crypto.tink.fpe;

import org.junit.jupiter.api.Test;

import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.b2s;
import static no.ssb.crypto.tink.fpe.util.ByteArrayUtil.s2b;
import static org.assertj.core.api.Assertions.assertThat;

class ByteArrayUtilTest {

    @Test
    void s2b2s() {
        assertThat(b2s(s2b("Foo æøå"))).isEqualTo("Foo æøå");
    }

}