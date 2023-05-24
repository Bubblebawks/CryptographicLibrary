import java.math.BigInteger;

public class ED488Goldilocks {
    private BigInteger x;
    private BigInteger y;

    public static ED488Goldilocks G = new ED488Goldilocks(BigInteger.valueOf(18), false);

    private static final BigInteger p = new BigInteger("2").pow(448).subtract(new BigInteger("2").pow(224)).subtract(BigInteger.ONE);
    private static final BigInteger d = new BigInteger("-39081");
    public static final BigInteger r = new BigInteger("2446").subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));


    ED488Goldilocks(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    ED488Goldilocks() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    ED488Goldilocks(BigInteger x, boolean leastYBit) {
        this.x = x;

        BigInteger int1 = BigInteger.ONE.subtract(x.modPow(BigInteger.valueOf(2), p));
        BigInteger int2 = BigInteger.ONE.add(new BigInteger("376014").multiply(x.modPow(BigInteger.valueOf(2), p)));
        BigInteger int3 = int1.multiply(int2.modInverse(p));

        BigInteger root = sqrt(int3, p, leastYBit);

        if (root != null) {
            this.y = root;
        }
        //if not acceptable, use the default?
        else {
            this.y = BigInteger.ONE;
        }
    }
    /* this one and the one above it are computing the same thing, compare these to the one in the doc to see which is a better fit
    public ED488Goldilocks(BigInteger x, boolean leastSignificantBit) {
        // Construct a curve point from x coordinate and the least significant bit of y
        this.x = x;
        // Compute y using the equation: y^2 = (1 - dx^2)/(1 + dx^2)
        BigInteger x2 = x.pow(2).mod(p);
        BigInteger numerator = BigInteger.ONE.subtract(d.multiply(x2)).mod(p);
        BigInteger denominator = BigInteger.ONE.add(d.multiply(x2)).mod(p);
        this.y = modularSqrt(numerator, denominator);
        // Adjust the sign of y based on the leastSignificantBit
        if (this.y.mod(BigInteger.TWO).equals(BigInteger.ONE) != leastSignificantBit) {
            this.y = p.subtract(this.y).mod(p);
        }
    }

     */

    /**
     * method to compare points for equality
     * @param Point point being compared
     * @return true or false whether the point is equal or not
     */
    public boolean equals(ED488Goldilocks Point) {
        return this.x.equals(Point.getX()) && this.y.equals(Point.getY());
    }

    /**
     * (from project description)
     * Compute a square root of v mod p with a specified
     * least significant bit, if such a root exists.
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    /**
     * given two points, use Edwards point addition formula to get the sum
     * @param p1 point 1
     * @param p2 point 2
     * @return a new point that is the sum of two given points
     */
     static ED488Goldilocks pointAdd(ED488Goldilocks p1, ED488Goldilocks p2){
        BigInteger x1 = p1.x;
        BigInteger x2 = p2.x;
        BigInteger y1 = p1.y;
        BigInteger y2 = p2.y;

        BigInteger xy1 = x1.multiply(y2).add(y1.multiply(x2));
        BigInteger xy2 = x1.multiply(x2).multiply(y1.multiply(y2)).multiply(d).add(BigInteger.ONE);

        BigInteger x = xy1.multiply(xy2.modInverse(p)).mod(p);
        BigInteger y = y1.multiply(y2).subtract(x1.multiply(x2)).multiply(xy2.modInverse(p)).mod(p);

        return new ED488Goldilocks(x, y);
     }
    public static ED488Goldilocks scalarMultiply(ED488Goldilocks P, BigInteger k) {
        ED488Goldilocks result = new ED488Goldilocks();
        ED488Goldilocks current = P;

        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) {
                result = pointAdd(result, current);
            }
            current = pointAdd(current, current);
            k = k.shiftRight(1);
        }
        return result;
    }
    ED488Goldilocks opposite() {
         return new ED488Goldilocks(x.modInverse(p), y);
    }
    private static final int TO_RETURN_LENGTH = 67;

    public byte[] toByte() {
        byte[] xBytes = x.toByteArray();
        int numZeroes = 66 - xBytes.length;
        byte ybit = y.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO) ? (byte) 0 : (byte) 1;

        byte[] toReturn = new byte[TO_RETURN_LENGTH];
        System.arraycopy(xBytes, 0, toReturn, numZeroes, xBytes.length);
        toReturn[66] = ybit;

        return toReturn;
    }

}
