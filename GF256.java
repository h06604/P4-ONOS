package org.onosproject.p4tutorial.mytunnel;
public class GF256 {
    private static final int GEN_POLY = 0x11D; // a generator polynomial of GF(256)

    /**
     * lookup-tables for faster operations. This is public so that I can use
     * it for performance tests
     */
    public static final int[] LOG_TABLE = new int[256]; // = log_g(index) (log base g)

    /**
     * lookup-tables for faster operations. This is public so that I can use
     * it for performance tests
     */
    public static final int[] ALOG_TABLE = new int[1025]; // = pow(g, index); 512 * 2 + 1

    /*
     * initialize the lookup tables
     */
    static {
        LOG_TABLE[0] = 512;
        ALOG_TABLE[0] = 1;

        for (int i = 1; i < 255; i++) {
            int next = ALOG_TABLE[i - 1] * 2;
            if (next >= 256) {
                next ^= GEN_POLY;
            }

            ALOG_TABLE[i] = next;
            LOG_TABLE[ALOG_TABLE[i]] = i;
        }

        ALOG_TABLE[255] = ALOG_TABLE[0];
        LOG_TABLE[ALOG_TABLE[255]] = 255;

        for (int i = 256; i < 510; i++) { // 2 * 255
            ALOG_TABLE[i] = ALOG_TABLE[i % 255];
        }

        ALOG_TABLE[510] = 1; // 2 * 255

        for (int i = 511; i < 1020; i++) { // 2 * 255 + 1; 4 * 255
            ALOG_TABLE[i] = 0;
        }
    }

    /* arithmetic operations */

    /**
     * Performs an addition of two numbers in GF(256). (a + b)
     *
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a + b</i> in GF(256) (will be in range 0 - 255)
     */
    public static int add(int a, int b) {
        return a ^ b;
    }

    /**
     * Performs a subtraction of two numbers in GF(256). (a - b)<br>
     * <b>NOTE:</b> addition and subtraction are the same in GF(256)
     *
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a - b</i> in GF(256) (will be in range 0 - 255)
     */
    public static int sub(int a, int b) {
        return a ^ b;
    }

    /**
     * Performs a multiplication of two numbers in GF(256). (a × b)
     *
     * @param a number in range 0 - 255
     * @param b number in range 0 - 255
     * @return the result of <i>a × b</i> in GF(256) (will be in range 0 - 255)
     */
    public static int mult(int a, int b) {
        return ALOG_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
    }

    /**
     * Performs an exponentiation of two numbers in GF(256). (a<sup>p</sup>)
     *
     * @param a number in range 0 - 255
     * @param p the exponent; a number in range 0 - 255
     * @return the result of <i>a<sup>p</sup></i> in GF(256) (will be in range 0 - 255)
     */
    public static int pow(int a, int p) {
        // The use of 512 for LOG[0] and the all-zero last half of ALOG cleverly
        // avoids testing 0 in mult, but can't survive arbitrary p*...%255 here.
        if (0 == a && 0 != p) {
            return 0;
        }
        return ALOG_TABLE[p * LOG_TABLE[a] % 255];
    }

    /**
     * Computes the inverse of a number in GF(256). (a<sup>-1</sup>)
     *
     * @param a number in range 0 - 255
     * @return the inverse of a <i>(a<sup>-1</sup>)</i> in GF(256) (will be in range 0 - 255)
     */
    public static int inverse(int a) {
        return ALOG_TABLE[255 - (LOG_TABLE[a] % 255)];
    }

    public static int div(int a, int b) {
        if (b == 0) { // a / 0
            throw new ArithmeticException("Division by 0");
        }

        return ALOG_TABLE[LOG_TABLE[a] + 255 - LOG_TABLE[b]];
    }

    public static int evaluateAt(int coeffs[], int x) {
        int degree = coeffs.length - 1;

        /* @author flexiprovider */
        int result = coeffs[degree];
        for (int i = degree - 1; i >= 0; i--) {
            result = add(mult(result, x), coeffs[i]);
        }
        return result;
    }

    public static int getFieldSize() {
        return 256;
    }
}
