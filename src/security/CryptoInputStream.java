package security;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CryptoInputStream extends FilterInputStream {
  protected Hash hash;
  protected byte[] K;
  protected byte[] buffer;
  protected int pointer;

  public CryptoInputStream(InputStream socket, byte[] key, Hash hash) {
    super(socket);
    this.hash = hash;
    this.K = key;
    this.pointer = 0;
  }

  public int available() throws IOException {
    int available = super.available();
    return available / this.hash.getPacketSize() * this.hash.getNumberOfDataBytes();
  }

  public int read() throws IOException {
    if (this.pointer == 0) {
      int index = 0;
      byte[] packetSize = new byte[this.hash.getPacketSize()];

      for(int i = 0; i < this.hash.getPacketSize(); ++i) {
        int readInput = super.in.read();
        if (readInput == -1) {
          if (i == 0) {
            return -1;
          }

          throw new IOException("Error in reading data");
        }

        packetSize[index++] = (byte)readInput;
      }

      try {
        packetSize = OneTimeKey.xor(packetSize, this.K);
        this.buffer = this.hash.unpack(packetSize);
      } catch (RuntimeException e) {
        e.printStackTrace();
      } catch (Exception e) {
        throw new IOException("error in reading");
      }
    }

    byte bufferPointer = this.buffer[this.pointer];
    int bufferLength = this.buffer.length;
    this.pointer = (this.pointer + 1) % bufferLength;
    return bufferPointer;
  }

  public int read(byte[] buffer, int startOffset, int dataLength ) throws IOException {
    if (buffer == null) {
      throw new NullPointerException("Empty Buffer");
    } else {
      int packetSize = this.hash.getPacketSize();
      int numberOfDataBytes = this.hash.getNumberOfDataBytes();
      int startPacketIndex = startOffset / numberOfDataBytes;
      int startByteOffset = startOffset % numberOfDataBytes;
      int numPacketsToRead  = (dataLength + startByteOffset) / packetSize;
      int lastPacketByteCount  = (dataLength  + startByteOffset) % packetSize;
      if (lastPacketByteCount  != 0) {
        ++numPacketsToRead ;
      }

      byte[] encryptedData = new byte[numPacketsToRead  * packetSize];
      int dataStartIndex  = startPacketIndex * packetSize;
      int dataEndIndex  = numPacketsToRead  * packetSize;

      try {
        if (super.available() >= dataEndIndex ) {
          int bytesRead  = super.in.read(encryptedData, dataStartIndex , dataEndIndex );
          if (bytesRead  == -1) {
            return bytesRead ;
          } else {
            byte[] decryptedData = OneTimeKey.xor(encryptedData, this.K);
            decryptedData = this.hash.unpack(decryptedData);
            System.arraycopy(decryptedData, 0, buffer, 0, decryptedData.length);
            return bytesRead  / packetSize * numberOfDataBytes;
          }
        } else {
          return 0;
        }
      } catch (Exception e) {
        System.out.println("Error in decryptinge");
        e.printStackTrace();
        return 0;
      }
    }
  }

  public long skip(long inp) throws IOException {
    for(long i = 0L; i < inp; ++i) {
      if (this.read() == -1) {
        return i;
      }
    }
    return inp;
  }
}
