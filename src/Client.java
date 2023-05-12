import security.Hash;
import security.OneTimeKey;
import security.RSA;
import security.SSLSocket;

import java.io.FileInputStream;
import java.util.Properties;

public class Client {
    private final SSLSocket socket;

    public Client(String hostName, int var2, String mickey) throws Exception {
        Properties properties = new Properties();
        FileInputStream fileInputStream = new FileInputStream(mickey + ".txt");
        properties.load(fileInputStream);
        fileInputStream.close();
        String company = properties.getProperty("company");
        RSA.PublicKey publicKey = new RSA.PublicKey(properties.getProperty("server.public_key").getBytes());
        RSA.PrivateKey privateKey = new RSA.PrivateKey(properties.getProperty("private_key").getBytes());
        byte pattern = (byte) Integer.parseInt(properties.getProperty("pattern"));
        int ndatabytes = Integer.parseInt(properties.getProperty("ndatabytes"));
        int ncheckbytes = Integer.parseInt(properties.getProperty("ncheckbytes"));
        int k = Integer.parseInt(properties.getProperty("k"));
        Hash hash = new Hash(ndatabytes, ncheckbytes, pattern, k);
        byte[] cipher = RSA.cipher(company.getBytes(), privateKey);
        byte[] newKey = OneTimeKey.newKey(ndatabytes + ncheckbytes + 1);
        byte[] cipher1 = RSA.cipher(newKey, publicKey);
        byte[] check = RSA.cipher(mickey.getBytes(), publicKey);
        this.socket = new SSLSocket(hostName, var2, check, cipher, cipher1, newKey, hash);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("java Client <host> <port> <name>");
            System.exit(1);
        }

        String hostName = args[0];
        int port = Integer.parseInt(args[1]);
        String mickey = args[2];
        (new Client(hostName, port, mickey)).execute();
    }

    public void execute() throws Exception {
        int input;
        int outputCounter = 0;
        int inputCounter = 0;
        while ((input = System.in.read()) != -1) {
            this.socket.getOutputStream().write(input);
            if ((char) input == '\n' || (char) input == '\r') {
                this.socket.getOutputStream().flush();
            }
            ++outputCounter;
        }
        this.socket.getOutputStream().flush();
        while ((input = this.socket.getInputStream().read()) != -1) {
            System.out.write(input);
            if (++inputCounter == outputCounter) break;
        }
        System.out.println();
        System.out.println("wrote " + inputCounter + " bytes");
        this.socket.close();
    }
}
