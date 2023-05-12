package security;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;

public class SSLSocket extends Socket {
  protected byte[] key;
  protected Hash hash;
  protected InputStream cryptoIn;
  protected OutputStream cryptoOut;
  protected Socket socket;

  public SSLSocket(String var1, int var2, InetAddress var3, int var4, byte[] var5, byte[] var6, byte[] var7, byte[] var8, Hash var9) throws IOException {
    super(var1, var2, var3, var4);
    this.handshake(var5, var6, var7);
    this.key = var8;
    this.hash = var9;
  }

  public SSLSocket(String var1, int var2, byte[] var3, byte[] var4, byte[] var5, byte[] var6, Hash var7) throws IOException {
    super(var1, var2);
    this.handshake(var3, var4, var5);
    this.key = var6;
    this.hash = var7;
  }

  public SSLSocket(InetAddress var1, int var2, InetAddress var3, int var4, byte[] var5, byte[] var6, byte[] var7, byte[] var8, Hash var9) throws IOException {
    super(var1, var2, var3, var4);
    this.handshake(var5, var6, var7);
    this.key = var8;
    this.hash = var9;
  }

  public SSLSocket(InetAddress var1, int var2, byte[] var3, byte[] var4, byte[] var5, byte[] var6, Hash var7) throws IOException {
    super(var1, var2);
    this.handshake(var3, var4, var5);
    this.key = var6;
    this.hash = var7;
  }

  public SSLSocket(Socket var1, byte[] var2, Hash var3) {
    this.socket = var1;
    this.key = var2;
    this.hash = var3;
  }

  public void close() throws IOException {
    if (this.socket == null) {
      super.close();
    } else {
      this.socket.close();
    }
  }

  public InputStream getCryptedInputStream() throws IOException {
    return super.getInputStream();
  }

  public InputStream getInputStream() throws IOException {
    if (this.cryptoIn == null) {
      InputStream socket = this.socket != null ? this.socket.getInputStream() : super.getInputStream();
      this.cryptoIn = new CryptoInputStream(socket, this.key, this.hash);
    }

    return this.cryptoIn;
  }

  public OutputStream getOutputStream() throws IOException {
    if (this.cryptoOut == null) {
      OutputStream socket = this.socket != null ? this.socket.getOutputStream() : super.getOutputStream();
      this.cryptoOut = new CryptoOutputStream(socket, this.key, this.hash);
    }

    return this.cryptoOut;
  }

  protected void handshake(byte[] data1, byte[] data2, byte[] data3) throws IOException {
    int escapeCounter = 0;

    for (byte b : data1) {
      if (b == 33 || b == 92) {
        ++escapeCounter;
      }
    }

    for (byte b : data2) {
      if (b == 33 || b == 92) {
        ++escapeCounter;
      }
    }

    for (byte b : data3) {
      if (b == 33 || b == 92) {
        ++escapeCounter;
      }
    }

    byte[] escapedData = new byte[data1.length + data2.length + data3.length + escapeCounter + 4];
    int index = 1;
    escapedData[0] = 33;

    for (byte b : data1) {
      if (b == 33 || b == 92) {
        escapedData[index++] = 92;
      }
      escapedData[index++] = b;
    }

    escapedData[index++] = 33;

    for (byte b : data2) {
      if (b == 33 || b == 92) {
        escapedData[index++] = 92;
      }
      escapedData[index++] = b;
    }

    escapedData[index++] = 33;

    for (byte b : data3) {
      if (b == 33 || b == 92) {
        escapedData[index++] = 92;
      }

      escapedData[index++] = b;
    }

    escapedData[index] = 33;
    super.getOutputStream().write(escapedData);
    super.getOutputStream().flush();
  }

  public String toString() {
    return "Crypto(" + this.socket + ')';
  }
}
