package security;

import java.math.BigInteger;

public class Hash {
  private int nDatabytes;
  private int nCheckbytes;
  private byte pattern;
  private int k;

  public Hash(int nDataBytes, int nCheckBytes, byte pattern, int k) {
    this.nDatabytes = nDataBytes;
    this.nCheckbytes = nCheckBytes;
    this.pattern = pattern;
    this.k = k;
  }

  public int getNumberOfDataBytes() {
    return this.nDatabytes;
  }

  public int getPacketSize() {
    return this.nDatabytes + this.nCheckbytes + 1;
  }

  public static void main(String[] args) throws Exception {
    if (args.length < 5) {
      System.out.println("java security.Hash <databytes> <checkbytes> <pattern> <k> <text> [ <text> ... ]");
      System.exit(1);
    }

    int dataBytes = Integer.parseInt(args[0]);
    int var2 = Integer.parseInt(args[1]);
    byte var3 = (byte)Integer.parseInt(args[2]);
    int var4 = Integer.parseInt(args[3]);

    for(int var5 = 4; var5 < args.length; ++var5) {
      byte[] var6 = pack(args[var5].getBytes(), dataBytes, var2, var3, var4);
      System.out.println("packed Bytes");
      System.out.println(new String(var6));
      System.out.println("unpacked Bytes");
      System.out.println(new String(unpack(var6, dataBytes, var2, var3, var4)));
    }

  }

  public byte[] pack(byte[] var1) {
    return pack(var1, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
  }

  public byte[] pack(byte[] var1, int var2) {
    byte[] var3 = new byte[var2];
    System.arraycopy(var1, 0, var3, 0, var2);
    return pack(var3, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
  }

  public static byte[] pack(byte[] message, int dataBytes, int checkBytes, byte pattern, int k) {
    if (dataBytes > 256) {
      throw new IllegalArgumentException("Maximum size of dataBytes is " + 256);
    }
    int messageLength = message.length;
    int packetSize = dataBytes + checkBytes + 1;
    int numPackets = (messageLength + dataBytes - 1) / dataBytes;
    byte[] packetData = new byte[numPackets * packetSize];

    int messageIndex = 0;
    for (int i = 0; i < numPackets; i++) {
      int packetDataBytes = (i + 1) * dataBytes > messageLength ? messageLength % dataBytes : dataBytes;
      packetData[i * packetSize] = (byte) packetDataBytes;
      long checksum = 0;
      for (int j = 0; j < packetDataBytes; j++) {
        byte b = message[messageIndex++];
        packetData[i * packetSize + j + 1] = b;
        checksum += (pattern & b) * k;
      }
      checksum %= Math.pow(2, 8 * checkBytes);
      byte[] checksumBytes = BigInteger.valueOf(checksum).toByteArray();
      int numChecksumBytes = checksumBytes.length;
      for (int j = 0; j < checkBytes; j++) {
        int index = i * packetSize + dataBytes + j + 1;
        packetData[index] = checkBytes - j > numChecksumBytes ? 0 : checksumBytes[j - (checkBytes - numChecksumBytes)];
      }
    }
    return packetData;
  }
  public byte[] unpack(byte[] var1) throws Exception {
    return unpack(var1, this.nDatabytes, this.nCheckbytes, this.pattern, this.k);
  }

  public static byte[] unpack(byte[] packet, int dataBytes, int checkBytes, byte pattern, int k) throws Exception {
    if (dataBytes > 256) {
      throw new RuntimeException("Maximum size of databytes is 256");
    }
    int packetLength = packet.length;
    int packetSize = 1 + dataBytes + checkBytes;
    if (packetLength % packetSize != 0) {
      throw new Exception("Packet Size is wrong");
    }
    int messageLength = 0;
    for (int i = 0; i < packetLength / packetSize; ++i) {
      messageLength += packet[i * packetSize];
    }
    byte[] message = new byte[messageLength];
    int messageIndex = 0;
    int packetIndex = 0;

    for (int i = 0; i < packetLength / packetSize; ++i) {
      int dataLength = packet[i * packetSize];
      long checksum = 0L;
      ++messageIndex;
      for (int j = 0; j < dataLength; ++j) {
        byte dataByte = packet[messageIndex];
        ++messageIndex;
        checksum += (dataByte & pattern) * k;
        message[packetIndex] = dataByte;
        ++packetIndex;
      }
      if (dataLength < dataBytes) {
        messageIndex += dataBytes - dataLength;
      }
      checksum %= (1L << (8 * checkBytes));
      int checksumIndex = i * packetSize + dataBytes + 1;
      for (int j = 0; j < checkBytes; ++j) {
        byte checksumByte = packet[checksumIndex + j];
        byte expectedChecksumByte = (byte) (checksum >> (8 * (checkBytes - j - 1)));
        if (checksumByte != expectedChecksumByte) {
          throw new Exception("wrong checksum");
        }
      }
      messageIndex += checkBytes;
    }
    return message;
  }
}
