package security;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

public class OneTimeKey {
  public OneTimeKey() {
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.out.println("java security.OneTimeKey <key>  <text> [ <text> ... ]");
      System.exit(1);
    }

    byte[] key = args[0].getBytes();

    for (int i = 1; i < args.length; ++i) {
      System.out.println("Input Message " + args[i]);
      byte[] encoded = OneTimeKey.xor(args[i].getBytes(), key);
      System.out.println("encoded to " + new String(encoded));
      byte[] decoded = OneTimeKey.xor(encoded, key);
      System.out.println("decoded to " + new String(decoded));
    }

  }

  public static byte[] newKey(int n) {
    return newKey(new Random(), n);
  }

  public static byte[] newKey(Random random, int n) {
    byte[] key = new byte[n];
    random.nextBytes(key);
    return key;
  }

  public static void printKey(byte[] random, OutputStream n) throws IOException {
    for(int i = 0; i < random.length; ++i) {
      n.write(random[i]);
    }

  }
  public static byte[] xor(byte[] message, byte[] key) {
    byte[] result = new byte[message.length];
    int messageIndex = 0;

    for (int i = 0; i < message.length / key.length; ++i) {
      for (int j = 0; j < key.length; ++j) {
        result[messageIndex] = (byte) (message[messageIndex] ^ key[j]);
        ++messageIndex;
      }
    }

    return result;
  }
}
