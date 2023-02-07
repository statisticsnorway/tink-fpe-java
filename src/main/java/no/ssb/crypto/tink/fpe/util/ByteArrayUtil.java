package no.ssb.crypto.tink.fpe.util;

import lombok.experimental.UtilityClass;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@UtilityClass
public class ByteArrayUtil {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Returns a byte array containing hexadecimal values parsed from the string
     * @param s          a character string containing hexadecimal digits
     * @return           a byte array with the values parsed from the string
     */
    public static byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Java 17 has java.util.HexFormat
     * @param byteArray  a byte array
     * @return           a hex string encoding of a number
     */
    public static String byteArrayToHexString(byte[] byteArray) {
        byte[] hexChars = new byte[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int v = byteArray[j] & 0xFF;
            hexChars[j * 2] = (byte) HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = (byte) HEX_ARRAY[v & 0x0F];
        }

        return new String(hexChars, StandardCharsets.UTF_8);
    }

    /**
     * used for debugging output
     * @param byteArray  a byte array
     * @return           a decimal string encoding of a number
     */
    public static String byteArrayToIntString(byte[] byteArray) {
        return Arrays.toString(byteArray);
    }

    public static String b2s(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            return null;
        }

        return new String(bArr, StandardCharsets.UTF_8);
    }

    public static byte[] s2b(String s) {
        if (s == null || s.length() == 0) {
            return null;
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

}
