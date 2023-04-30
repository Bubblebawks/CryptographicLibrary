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

    private byte[] inData;

    //Used for theta function
    BigInteger[] bc = new BigInteger[5];
    BigInteger t;

    BigInteger[] myState = new BigInteger[25]; //each element is a "lane" of the internal state?


    //message digest length
    private final int mdLength;

    //message size
    private final int mSize = 72;

    //previous byte track
    private int pt;

    KMACXOF256(byte[] K, byte[] X, int L, String S){
        //conversion of bits to bytes
        mdLength = L / 8;

        // round constant array
        for (int i = 0; i < 24; i++) {
            RC[i] = new BigInteger(roundConst[i], 16);
        }
        byte[] x1 = bytepad(encodeString(K), 168);
        byte[] x3 = rightEncode(BigInteger.ZERO);
        byte[] newX = new byte[x1.length + X.length + x3.length];

        int index = 0;
        for (byte b : x1) {
            newX[index] = b;
            index++;
        }
        for (byte b: X) {
            newX[index] = b;
            index++;
        }
        for (byte b: x3) {
            newX[index] = b;
            index++;
        }
        cSHAKE256(newX, L, "KMAC", S);
    }

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
        ret[retLength-2] = 0;
        ret[retLength-1] = 0;

        inData = ret;
    }


    byte[] rightEncode(BigInteger x) {
        byte[] retBytes = x.toByteArray();
        byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
        byte[] totalBytes = new byte[retBytes.length + addBytes.length];

        System.arraycopy(retBytes, 0, totalBytes, 0, retBytes.length);
        System.arraycopy(addBytes, 0, totalBytes, retBytes.length, addBytes.length);

        return totalBytes;
    }


    byte[] leftEncode(BigInteger x) {
        byte[] retBytes = x.toByteArray();
        byte[] addBytes = BigInteger.valueOf(retBytes.length).toByteArray();
        byte[] totalBytes = new byte[retBytes.length + addBytes.length];

        System.arraycopy(addBytes, 0, totalBytes, 0, addBytes.length);
        System.arraycopy(retBytes, 0, totalBytes, addBytes.length, retBytes.length);

        return totalBytes;
    }

    public byte[] encodeString(byte[] s) {
        byte[] first = leftEncode(BigInteger.valueOf(s.length));
        byte[] output = Arrays.copyOf(first, first.length + s.length);
        System.arraycopy(s, 0, output, first.length, s.length);
        return output;
    }

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


    public byte[] retrieveData() {
        return sha3(inData, mdLength);
    }

    public void keccakf(BigInteger[] state) {
        endianConversion();
        for (int r = 0 ; r < 24; r++) {
            for (int i = 0; i < 5; i++) { //theta
                bc[i] = state[i].xor(state[i+5]).xor(state[i+10]).xor(state[i+15]).xor(state[i+20]);
            }
            for (int i = 0; i < 5; i++) {
                t = bc[(i+4) % 5].xor(ROTL64(bc[(i+1) % 5], 1));

                for (int j = 0; j < 25; j += 5) {
                    state[j + 1] = state[j+1].xor(t);
                }
            }
            //rho and pi
            t = state[1];
            for (int i = 0; i < 24; i++) {
                int j = keccakf_piln[i];
                bc[0] = state[j];
                state[j] = ROTL64(t, rotationOffset[i]);
                t = bc[0];
            }

            //chi
            for (int j = 0; j < 25; j+=5) {
                System.arraycopy(state, j, bc, 0, 5);
                for (int i = 0; i < 5; i++)
                    state[j+i] = state[j+1].xor(bc[(i+1)% 5].not()).and(bc[(i+2)%5]);
            }
            //iota
            state[0] = state[0].xor(RC[r]);
        }
        endianConversion();
    }
    //initialize context
    void sha3_init(int mdlen) {
        for (int i = 0; i < 25; i++)
            myState[i] = BigInteger.ZERO;
        pt = 0;
    }

    //update sha3 w/data
    void sha3_update(byte[] data) {
        byte[] byteState = bigIntToByte(myState);
        int j = pt;
        for (byte datum : data) {

            byteState[j++] ^= datum;

            if (j >= mSize) {
                myState = byteToBigInt(byteState);
                keccakf(myState);
                j = 0;
            }
        }
        myState = byteToBigInt(byteState);
        pt = j;

    }

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

    static BigInteger[] byteToBigInt(byte[] byteArr) {
        BigInteger[] intState = new BigInteger[25];

        for (int i = 0; i < 200; i+=8) {
            byte[] currBytes = new byte[8];
            System.arraycopy(byteArr, i, currBytes, 0, 8);
            intState[i/8] = new BigInteger(currBytes);
        }

        return intState;
    }

    //hash output from length
    byte[] sha3_final() {
        byte[] md = new byte[mdLength];
        int curr = 0;

        byte[] stateBytes = bigIntToByte(myState);

        stateBytes[pt] ^= 0x06;
        stateBytes[mSize - 1] ^= 0x80;
        myState = byteToBigInt(stateBytes);
        keccakf(myState);

        stateBytes = bigIntToByte(myState);

        for (int x = 0; x < (mdLength / mSize); x++) {
            System.arraycopy(stateBytes, 0, md, curr, mSize);
            curr += mSize;
            keccakf(myState);
            stateBytes = bigIntToByte(myState);
        }
        System.arraycopy(stateBytes, 0, md, curr, mdLength % mSize);
        return md;
    }

    //hash from data given
    byte[] sha3(byte[] in, int mdLen) {
        sha3_init(mdLen);
        sha3_update(in);
        return sha3_final();
    }

    public BigInteger ROTL64(BigInteger x, int y) {
        return x.shiftLeft(y).or(x.shiftRight(64 - y));
    }

    private void endianConversion() {
        for (int i = 0; i < 25; i++) {
            byte[] curr = myState[i].toByteArray();
            byte[] rev = new byte[curr.length];

            for (int x = 0; x < curr.length; x++) {
                rev[x] = curr[curr.length - x - 1];
            }
            myState[i] = new BigInteger(rev);
        }
    }

    public String byteToString(byte toConvert) {
        String toReturn = "";

        byte byteMask = 0b0000001;

        for (int bitIndex = 0; bitIndex < 8; bitIndex++) {
            int bit = byteMask & toConvert;
            if (bit == 0) toReturn = "0" + toReturn;
            else toReturn = "1" + toReturn;
            byteMask = (byte) (byteMask * 2);
        }

        return toReturn;
    }
}
