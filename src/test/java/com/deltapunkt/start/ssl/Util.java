package com.deltapunkt.start.ssl;

public class Util {
    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();
    public static String toHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes)
        {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }

        return sb.toString();
    }

    public static void log(String message) {
        System.out.println(message);
    }
}
