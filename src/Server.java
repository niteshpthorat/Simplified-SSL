import security.RSA;
import security.SSLServerSocket;
import security.SSLSocket;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class Server
        implements Runnable {
  private RSA.PrivateKey serverPrivateKey;
  private Properties prop;
  private SSLServerSocket server;
  private int port;

  public Server() throws IOException {
    this.serverPrivateKey = loadPrivateKey();
    this.prop = loadUsers();
    this.port = getPort();

    this.server = new SSLServerSocket(this.port, this.serverPrivateKey, this.prop);
  }

  private RSA.PrivateKey loadPrivateKey() throws IOException {
    String privateKeyLocation = System.getProperty("server.private_key", "private_key.txt");
    try (FileInputStream fis = new FileInputStream(privateKeyLocation)) {
      return new RSA.PrivateKey(fis);
    }
  }

  private Properties loadUsers() throws IOException {
    String usersLocation = System.getProperty("server.users", "users.txt");
    try (FileInputStream fis = new FileInputStream(usersLocation)) {
      Properties prop = new Properties();
      prop.load(fis);
      return prop;
    }
  }

  private int getPort() {
    String port = System.getProperty("server.port");
    return (port != null) ? Integer.parseInt(port) : 5000;
  }

  public static void main(String[] paramArrayOfString)
          throws Exception {
    new Server().run();
  }

  public void run() {
    while (true)
      try {
        new Thread(new Server.RequestHandler((SSLSocket) this.server.accept())).run();
      } catch (Exception localException) {
        localException.printStackTrace();
      }
  }

  public class RequestHandler
          implements Runnable {
    private SSLSocket socket;

    public RequestHandler(SSLSocket arg2) {
      this.socket =  arg2;
    }

    public void run() {
      try {
        System.out.println("Connection established");

        int readByte;
        while ((readByte = this.socket.getInputStream().read()) != -1) {
          if ((readByte >= 'a') && (readByte <= 'z')) {
            readByte -= 32;
          } else if ((readByte >= 'A') && (readByte <= 'Z')) {
            readByte += 32;
          }

          this.socket.getOutputStream().write(readByte);

          if (this.socket.getInputStream().available() == 0) {
            this.socket.getOutputStream().flush();
          }
        }

        this.socket.getOutputStream().flush();
        socket.close();
        System.out.println("Connection closed");
      } catch (IOException ex) {
        ex.printStackTrace();
      }
    }
  }
}