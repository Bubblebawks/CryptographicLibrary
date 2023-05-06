/*
Vivian Tran, Gil Rabara, Andrew John Nguyen
TCSS 487 Cryptography Project (Part 1) - KMACXOF256
5/7/2023
 */

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class KMACXOF256 {
    private final BigInteger[] RC = new BigInteger[24];

    //round constant array
    private final String[] roundConst = {"0000000000000001", "0000000000008082", "800000000000808A", "8000000080008000",
            "000000000000808B", "0000000080000001", "8000000080008081", "8000000000008009", "000000000000008A",
            "0000000000000088", "0000000080008009", "000000008000000A", "000000008000808B","800000000000008B", "8000000000008089",
            "8000000000008003", "8000000000008002", "8000000000000080", "000000000000800A", "800000008000000A",
            "8000000080008081", "8000000000008080", "0000000080000001", "8000000080008008"};

    int[] rotationOffset = {1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44};

    int[] keccakf_piln = {10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    private byte[] bytes;

    // for theta function
    BigInteger[] bc = new BigInteger[5];
    BigInteger t;
    BigInteger tPrime;

    BigInteger[] currState = new BigInteger[25];


    //message digest length
    private final int mdLength;

    //message size
    private final int mSize = 72;

    //previous byte
    private int prevByte;

    /**
     * KMAC function that takes information and produces output given length
     * @param K data of given key
     * @param X data given in order to encrypt
     * @param L length of output
     * @param S output for strings
     */
    KMACXOF256(byte[] K, byte[] X, int L, String S){
        //conversion of bits to bytes
        mdLength = L / 8;

        // round constant array
        for (int i = 0; i < 24; i++) {
            RC[i] = new BigInteger(roundConst[i], 16);
        }
        byte[] x1;
        if (K.length < 168) {
            x1 = bytepad(encodeString(K), 168);
        } else {
            x1 = Arrays.copyOf(K, 168);
        }
        byte[] x3 = rightEncode(BigInteger.ZERO);
        byte[] newX = new byte[x1.length + X.length + x3.length];

        int i = 0;
        for (byte b : x1) {
            newX[i] = b;
            i++;
        }
        for (byte b: X) {
            newX[i] = b;
            i++;
        }
        for (byte b: x3) {
            newX[i] = b;
            i++;
        }

        cSHAKE256(newX, L, "KMAC", S);
    }

    /**
     * perform cSHAKE256 hash of input
     * @param X input data given
     * @param L output length
     * @param N name of function
     * @param S character string
     */
    void cSHAKE256(byte[] X, int L, String N, String S) {
        byte[] n = encodeString(N.getBytes(StandardCharsets.UTF_8));
        byte[] s = encodeString(S.getBytes(StandardCharsets.UTF_8));

        int newXLength = n.length + s.length;
        byte[] newX = new byte[newXLength];
        System.arraycopy(n, 0, newX, 0, n.length);
        System.arraycopy(s, 0, newX, n.length, s.length);

        byte[] retStart = bytepad(newX, 136);

        int retLength = retStart.length + X.length + 2;
        byte[] ret = new byte[retLength];
        System.arraycopy(retStart, 0, ret, 0, retStart.length);
        System.arraycopy(X, 0, ret, retStart.length, X.length);

        ret[retLength-1] = (byte) 0x80;
        ret[retStart.length] ^= 0x80;

        bytes = ret;

        // initialize t and tPrime to the same value
        t = new BigInteger(1, retStart);
        tPrime = new BigInteger(1, retStart);
    }


    /**
     * takes big int and right encode byte array
     * @param x big integer to encode
     * @return byte array that represent right encode of big int
     */
    byte[] rightEncode(BigInteger x) {
        byte[] retBytes = x.toByteArray();
        //byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
        byte[] addBytes = BigInteger.valueOf(retBytes.length * 8).toByteArray();

        byte[] totalBytes = new byte[retBytes.length + addBytes.length];

        System.arraycopy(retBytes, 0, totalBytes, 0, retBytes.length);
        System.arraycopy(addBytes, 0, totalBytes, retBytes.length, addBytes.length);

        return totalBytes;
    }


    /**
     * takes big int and left encode byte array
     * @param x big integer to encode
     * @return byte array that represent left encode of big int
     */
    byte[] leftEncode(BigInteger x) {
        byte[] retBytes = x.toByteArray();
        //byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
        byte[] addBytes = BigInteger.valueOf(retBytes.length * 8).toByteArray();
        byte[] totalBytes = new byte[retBytes.length + addBytes.length];

        System.arraycopy(addBytes, 0, totalBytes, 0, addBytes.length);
        System.arraycopy(retBytes, 0, totalBytes, addBytes.length, retBytes.length);

        return totalBytes;
    }

    /**
     * input byte array and encode with left encode
     * @param s given input of byte array to encode
     * @return bytearray that has been encoded
     */
    public byte[] encodeString(byte[] s) {
        byte[] first = leftEncode(BigInteger.valueOf(s.length));
        byte[] output = Arrays.copyOf(first, first.length + s.length);
        System.arraycopy(s, 0, output, first.length, s.length);
        return output;
    }

    /**
     * take byte array and pad with zero
     * @param X byte array to be padded
     * @param w length of padded byte array
     * @return padded byte array of X
     */
    public byte[] bytepad(byte[] X, int w) {
        byte[] firstEncode = leftEncode(BigInteger.valueOf(w));
        byte[] z = new byte[firstEncode.length + X.length];
        System.arraycopy(firstEncode, 0, z, 0, firstEncode.length);
        System.arraycopy(X, 0, z, firstEncode.length, X.length);

        int zLen = z.length;
        int addZeroes = 0;
        while ((zLen + addZeroes) % 8 != 0 || (zLen + addZeroes) / 8 % w != 0) {
            addZeroes++;
        }

        return Arrays.copyOf(z, zLen + addZeroes);
    }

    /**
     * @return get hash of KMAC
     */
    public byte[] retrieveData() {
        return sha3(bytes);
    }

    /**
     * keccak permutation with operations: theta, rho, pi, cho, and iota
     * @param keccak big int array to apply
     */
    public void keccakf(BigInteger[] keccak) {
        endianConversion();
        for (int r = 0 ; r < 24; r++) {
            for (int i = 0; i < 5; i++) { //theta
                bc[i] = keccak[i].xor(keccak[i+5]).xor(keccak[i+10]).xor(keccak[i+15]).xor(keccak[i+20]);
            }
            for (int i = 0; i < 5; i++) {
                BigInteger[] tArr = new BigInteger[25];
                for (int j = 0; j < 25; j++) {
                    tArr[j] = keccak[j];
                }
                BigInteger t = bc[(i+4) % 5].xor(ROTL64(bc[(i+1) % 5], 1));

                for (int j = 0; j < 25; j += 5) {
                    tArr[j + 1] = tArr[j+1].xor(t);
                }
                System.arraycopy(tArr, 0, keccak, 0, tArr.length);
            }
            //rho and pi
            BigInteger t = keccak[1];
            BigInteger[] tPrimeArr = new BigInteger[24];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                tPrimeArr[i] = keccak[j];
                keccak[j] = ROTL64(t, rotationOffset[i]);
                t = tPrimeArr[i];
            }

            //chi
            for (int j = 0; j < 25; j+=5) {
                System.arraycopy(keccak, j, bc, 0, 5);
                for (int i = 0; i < 5; i++)
                    keccak[j+i] = keccak[j+1].xor(bc[(i+1)% 5].not()).and(bc[(i+2)%5]);
            }
            //iota
            keccak[0] = keccak[0].xor(RC[r]);
        }
        endianConversion();
    }


    /**
     * initialize SHA3
     */
    void sha3_init() {
        for (int i = 0; i < 25; i++)
            currState[i] = BigInteger.ZERO;
        prevByte = 0;
    }

    /**
     * update SHA3 with given data
     * @param data given to update
     */
    void sha3_update(byte[] data) {
        byte[] byteState = bigIntToByte(currState);
        int j = prevByte;
        for (byte datum : data) {

            byteState[j++] ^= datum;

            if (j >= mSize) {
                currState = byteToBigInt(byteState);
                keccakf(currState);
                j = 0;
            }
        }
        currState = byteToBigInt(byteState);
        prevByte = j;
    }

    /**
     * convert big int array to byte array
     * @param bigIntArr array to convert to byte array
     * @return byte array from given big int array
     */
    static byte[] bigIntToByte(BigInteger[] bigIntArr) {
        byte[] byteState = new byte[200];
        int index = 0;

        for (int i = 0; i < 24; i++) {
            long stateVal = bigIntArr[i].longValue();
            for (int j = 7; j >= 0; j--) {
                byteState[index++] = (byte) ((stateVal >> (8 * j)) & 0xFF);
            }
        }
        return byteState;
    }

    /**
     * convert byte array to big int array
     * @param byteArr given to convert to big int
     * @return big int array that was converted from given byte array
     */
    static BigInteger[] byteToBigInt(byte[] byteArr) {
        BigInteger[] intState = new BigInteger[25];

        for (int i = 0; i < 200; i+=8) {
            byte[] currBytes = new byte[8];
            System.arraycopy(byteArr, i, currBytes, 0, 8);
            intState[i/8] = new BigInteger(currBytes);
        }

        return intState;
    }

    /**
     * hash the length that was given
     * @return byte array with given length of hash
     */
    byte[] sha3_final() {
        byte[] md = new byte[mdLength];
        int curr = 0;

        byte[] stateBytes = bigIntToByte(currState);

        stateBytes[prevByte] ^= 0x06;
        stateBytes[mSize - 1] ^= 0x80;
        currState = byteToBigInt(stateBytes);
        keccakf(currState);

        stateBytes = bigIntToByte(currState);

        for (int x = 0; x < (mdLength / mSize); x++) {
            System.arraycopy(stateBytes, 0, md, curr, mSize);
            curr += mSize;
            keccakf(currState);
            stateBytes = bigIntToByte(currState);
        }
        System.arraycopy(stateBytes, 0, md, curr, mdLength % mSize);
        return md;
    }

    /**
     * hash from data that was given
     * @param in input byte array
     * @return hash of data
     */
    byte[] sha3(byte[] in) {
        sha3_init();
        sha3_update(in);
        return sha3_final();
    }

    /**
     * shifts bytes left or right based on value y
     * @param x bigint number to be rotated
     * @param y specifies number of bits to rotate
     * @return bigint rotated by the input number
     */
    public BigInteger ROTL64(BigInteger x, int y) {
        return x.shiftLeft(y).or(x.shiftRight(64 - y));
    }

    /**
     * convert endian from keccak operation
     */
    private void endianConversion() {
        for (int i = 0; i < 25; i++) {
            byte[] curr = currState[i].toByteArray();
            byte[] rev = new byte[curr.length];

            for (int x = 0; x < curr.length; x++) {
                rev[x] = curr[curr.length - x - 1];
            }
            currState[i] = new BigInteger(rev);
        }
    }
}
