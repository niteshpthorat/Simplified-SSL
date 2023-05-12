package security;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;

public class SSLServerSocket extends ServerSocket {
    protected RSA.PrivateKey sKR;
    protected Properties prop;

    public SSLServerSocket(int var1, int var2, InetAddress var3, RSA.PrivateKey var4, Properties var5) throws IOException {
        super(var1, var2, var3);
        this.sKR = var4;
    }

    public SSLServerSocket(int var1, int var2, RSA.PrivateKey var3, Properties var4) throws IOException {
        super(var1, var2);
        this.sKR = var3;
        this.prop = var4;
    }

    public SSLServerSocket(int var1, RSA.PrivateKey var2, Properties var3) throws IOException {
        super(var1);
        this.sKR = var2;
        this.prop = var3;
    }

    public Socket accept() throws IOException {
        Socket accept = super.accept();
        Object var2 = null;
        Hash hash = null;

        byte[] key;
        try {
            Object[] handshake = this.handshake(accept);
            key = (byte[]) handshake[0];
            hash = (Hash) handshake[1];
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        return new SSLSocket(accept, key, hash);
    }

    protected byte[] getGreetingToken(Socket socket) throws IOException {
        int i = 128;
        byte[] var3 = new byte[i];

        int var4;
        int input;
        byte[] var6;
        for (var4 = 0; (input = socket.getInputStream().read()) != 33; var3[var4++] = (byte) input) {
            if (input == -1) {
                throw new EOFException("Unexpected ended Greeting");
            }

            if (input == 92 && (input = socket.getInputStream().read()) == -1) {
                throw new EOFException("Unexpected ended Greeting");
            }

            if (var4 == i) {
                i += i / 2 + 1;
                var6 = new byte[i];
                System.arraycopy(var3, 0, var6, 0, var4);
                var3 = var6;
            }
        }

        var6 = new byte[var4];
        System.arraycopy(var3, 0, var6, 0, var4);
        return var6;
    }

    protected Object[] handshake(Socket var1) throws Exception {
        int inpu;
        do {
            if ((inpu = var1.getInputStream().read()) == 33) {
                byte[] greetingToken = this.getGreetingToken(var1);
                byte[] greetingToken1 = this.getGreetingToken(var1);
                byte[] greetingToken2 = this.getGreetingToken(var1);
                String user = new String(RSA.cipher(greetingToken, this.sKR));
                String puKey = this.prop.getProperty(user + ".public_key");
                if (puKey == null) {
                    throw new Exception("Unknow User: " + user);
                }

                RSA.PublicKey getPuKey = new RSA.PublicKey(puKey.getBytes());
                String company = new String(RSA.cipher(greetingToken1, getPuKey));
                if (!company.equals(this.prop.getProperty(user + ".company"))) {
                    throw new Exception("Wrong company (" + user + ':' + company + ")");
                }

                int nDataBytes = Integer.parseInt(this.prop.getProperty(user + ".ndatabytes"));
                int nCheckBytes = Integer.parseInt(this.prop.getProperty(user + ".ncheckbytes"));
                byte pattern = (byte) Integer.parseInt(this.prop.getProperty(user + ".pattern"));
                int k = Integer.parseInt(this.prop.getProperty(user + ".k"));
                return new Object[]{RSA.cipher(greetingToken2, this.sKR), new Hash(nDataBytes, nCheckBytes, pattern, k)};
            }
        } while (inpu != -1);

        throw new EOFException("Unfinished Greeting");
    }
}
