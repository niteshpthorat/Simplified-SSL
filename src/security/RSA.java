package security;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

public class RSA {
    public RSA() {
    }

    public static byte[] cipher(String input, Key key) throws Exception {
        return cipher(input.getBytes(), key);
    }

    public static byte[] cipher(byte[] message, Key key) {
        System.out.println("inCipher");
        byte[] messageLength = new byte[message.length + 1];
        messageLength[0] = 0;
        System.arraycopy(message, 0, messageLength, 1, message.length);
        byte[] interMediate = new BigInteger(messageLength).modPow(key.getKey(), key.getN()).toByteArray();
        if (interMediate[0] != 0) {
            return interMediate;
        }
        byte[] cipheredMessage = new byte[interMediate.length - 1];
        System.arraycopy(interMediate, 1, cipheredMessage, 0, interMediate.length - 1);
        return cipheredMessage;
    }

    public static KeyPair generateKeys(BigInteger numberP, BigInteger numberQ) {
        BigInteger multiplicationPQ = numberP.subtract(BigInteger.ONE).multiply(numberQ.subtract(BigInteger.ONE));
        BigInteger relativePrime = RSA.relativePrime(multiplicationPQ);
        BigInteger inversePrime = relativePrime.modInverse(multiplicationPQ);
        return new KeyPair(new PrivateKey(inversePrime, numberP.multiply(numberQ)), new PublicKey(relativePrime, numberP.multiply(numberQ)));
    }

    public static void main(String[] args) throws Exception {
        String primeSize = System.getProperty("prime_size");
        String primeCertainty = System.getProperty("prime_certainty");
        int primeSizeInt = primeSize == null ? 256 : Integer.parseInt(primeSize);
        int primeCertaintyInt = primeCertainty == null ? 5 : Integer.parseInt(primeCertainty);

        BigInteger numberP = new BigInteger(primeSizeInt, primeCertaintyInt, new Random());
        BigInteger numberQ = new BigInteger(primeSizeInt, primeCertaintyInt, new Random());
        KeyPair keyPair = generateKeys(numberP, numberQ);
        System.out.println(keyPair);
        if (args[0].equals("-help")) {
            System.out.println("java security.RSA -gen [ <text> ]");
            System.out.println("   - generate private (KR) and public (KU) keys");
            System.out.println("     and test them on <text> (optional)");
            System.out.println();
        } else if (args.length == 2) {
            byte[] input = args[1].getBytes();
            byte[] publicKey = cipher(input, keyPair.getPublicKey());
            byte[] privateKey = cipher(input, keyPair.getPrivateKey());
            System.out.println("KU(KR(M))=" + new String(cipher(publicKey, keyPair.getPrivateKey())));
            System.out.println("KR(KU(M))=" + new String(cipher(privateKey, keyPair.getPublicKey())));
        }
    }

    private static BigInteger relativePrime(BigInteger multiplicationPQ) {
        BigInteger relativePrime;
        Random random = new Random();
        int length = multiplicationPQ.toByteArray().length;
        BigInteger bigIntOne = BigInteger.ONE;
        do {
            byte[] newBytearray = new byte[length];
            random.nextBytes(newBytearray);
            relativePrime = new BigInteger(newBytearray).abs();
        } while (multiplicationPQ.gcd(relativePrime = relativePrime.mod(multiplicationPQ)).compareTo(bigIntOne) != 0);
        return relativePrime;
    }

    public static class Key {
        protected BigInteger key;
        protected BigInteger n;
        private static final BigInteger zero;

        static {
            zero = BigInteger.ZERO;
        }

        public Key() {
            this(zero, zero);
        }

        public Key(BigInteger key, BigInteger n) {
            this.key = key;
            this.n = n;
        }

        protected BigInteger getKey() {
            return this.key;
        }

        protected BigInteger getN() {
            return this.n;
        }

        public void read(InputStream var1) throws IOException {
            int n;
            while ((n = var1.read()) != 123) {
                switch (n) {
                    case 9:
                    case 10:
                    case 13:
                    case 32:
                        break;
                    default:
                        throw new IOException("Wrong Format");
                }
            }

            StringBuffer buffer = new StringBuffer(128);

            while ((n = var1.read()) != 44) {
                if (n == -1) {
                    throw new EOFException("Unexpected End of File");
                }

              buffer.append((char) n);
            }

            try {
                this.key = new BigInteger(buffer.toString());
            } catch (NumberFormatException e) {
                throw new IOException(e.toString());
            }

          buffer.setLength(0);

            while ((n = var1.read()) != 125) {
                if (n == -1) {
                    throw new EOFException("Unexpected End of File");
                }

              buffer.append((char) n);
            }

            try {
                this.n = new BigInteger(buffer.toString());
            } catch (NumberFormatException e) {
                throw new IOException(e.toString());
            }
        }

        public void read(byte[] input) throws IOException {
            this.read((InputStream) (new ByteArrayInputStream(input)));
        }

        public String toString() {
            return '{' + this.key.toString() + ',' + this.n.toString() + '}';
        }
    }

    public static class PublicKey extends Key {
        public PublicKey(InputStream input) throws IOException {
            this.read(input);
        }

        protected PublicKey(BigInteger var1, BigInteger var2) {
            super(var1, var2);
        }

        public PublicKey(byte[] var1) throws IOException {
            this.read(var1);
        }
    }

    public static class PrivateKey extends Key {
        public PrivateKey(InputStream var1) throws IOException {
            this.read(var1);
        }

        protected PrivateKey(BigInteger var1, BigInteger var2) {
            super(var1, var2);
        }

        public PrivateKey(byte[] var1) throws IOException {
            this.read(var1);
        }
    }

    public static class KeyPair {
        private PrivateKey kR;
        private PublicKey kU;

        public KeyPair(PrivateKey var1, PublicKey var2) {
            this.kR = var1;
            this.kU = var2;
        }

        public PrivateKey getPrivateKey() {
            return this.kR;
        }

        public PublicKey getPublicKey() {
            return this.kU;
        }

        public String toString() {
            return "KR=" + this.kR + "\r\n" + "KU=" + this.kU;
        }
    }
}
