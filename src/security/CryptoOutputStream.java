package security;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class CryptoOutputStream extends FilterOutputStream {
  protected Hash hash;
  protected byte[] K;
  private byte[] buffer;
  private int pointer;

  public CryptoOutputStream(OutputStream socket, byte[] k, Hash hash) {
    super(socket);
    this.hash = hash;
    this.K = k;
    int numberOfDataBytes = hash.getNumberOfDataBytes();
    this.buffer = new byte[numberOfDataBytes];
    this.pointer = 0;
  }

  public void flush() throws IOException {
    if (this.pointer != 0) {
      this.shallowFlush();
    }

    super.flush();
  }

  protected void shallowFlush() throws IOException {
    if (this.pointer != 0) {
      this.write(this.buffer, 0, this.pointer);
      this.pointer = 0;
    }

  }

  public void write(int var1) throws IOException {
    this.buffer[this.pointer++] = (byte)var1;
    if (this.pointer == this.buffer.length) {
      this.pointer = 0;
      this.write(this.buffer, 0, this.buffer.length);
    }

  }

  public void write(byte[] var1, int var2, int var3) throws IOException {
    byte[] var4 = new byte[var3];
    System.arraycopy(var1, var2, var4, 0, var3);

    try {
      byte[] var5 = this.hash.pack(var4);
      var5 = OneTimeKey.xor(var5, this.K);
      super.out.write(var5);
    } catch (Exception var7) {
      System.out.println(var7);
    }

  }
}
