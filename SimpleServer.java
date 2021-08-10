import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Files;
import java.math.BigInteger;
import java.io.ByteArrayOutputStream;

public class SimpleServer implements Runnable {

   // server's socket
    private ServerSocket s;
   // server's port
    private int port;
    private String[] userInfoArray;
    private BigInteger[] serverNed = new BigInteger[3];
    private BigInteger[] clientNde = new BigInteger[3];
    private BigInteger agreedKValue;
    private byte[] agreedKValueBytes;

    public SimpleServer(int p, String privateKeyFileName, String userInfoFileName) throws Exception {
        // open server socket and start listening
        s = new ServerSocket(port = p);
        
        //Isolate the d and n in the private key
        Path pathPrivateKeyFileName = Path.of(privateKeyFileName);
        String privateKey = Files.readString(pathPrivateKeyFileName);
        String privateKeyD = privateKey.split(",")[0];
        privateKeyD = privateKeyD.replaceAll("\\D+","");
        String publicN = privateKey.substring(privateKey.lastIndexOf(",") + 1);
        publicN = publicN.replaceAll("\\D+","");
        BigInteger[] serverKR = new BigInteger[2];
        serverKR[0] = new BigInteger(privateKeyD);
        serverKR[1] = new BigInteger(publicN);

        serverNed[0] = serverKR[1];
        serverNed[1] = new BigInteger("0");
        serverNed[2] = serverKR[0];
        BigInteger abc = new BigInteger(publicN);


        //divide up info 
        //[company name, ndatabytes, ncheckbytes, k, pattern, client d, client n, username]
        Path pathUserInfoFileName = Path.of(userInfoFileName);
        String allUserInfo = Files.readString(pathUserInfoFileName);
        String[] tempUserInfoArray = allUserInfo.split("\n");
        userInfoArray = new String[8];
        for (int i=0; i <tempUserInfoArray.length; i++) {
            userInfoArray[i] = tempUserInfoArray[i].substring(tempUserInfoArray[i].lastIndexOf("=") + 1);
        }
        userInfoArray[5] = tempUserInfoArray[5].split(",")[0];
        userInfoArray[5] = userInfoArray[5].replaceAll("\\D+","");
        userInfoArray[6] = tempUserInfoArray[5].substring(tempUserInfoArray[5].lastIndexOf(",") + 1).replaceAll("\\D+","");
        userInfoArray[7] = tempUserInfoArray[0].split("\\.")[0];

        clientNde[0] = new BigInteger(userInfoArray[6]);
        clientNde[1] = new BigInteger("0");
        clientNde[2] = new BigInteger(userInfoArray[5]);
    }

    public class RequestHandler implements Runnable {
        private Socket sock;

        private RequestHandler(java.net.Socket x) {
            sock = x;
        }

        public void run() {
            int trackByteArray = 0;
            byte[] curEncryptedByteArray;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            boolean connected = false;
            int packetLength = Integer.parseInt(userInfoArray[1]) + Integer.parseInt(userInfoArray[2]) + 1;
            byte[] lockedCurPacket;            

            try {
                int c;
                int byteNumber = 0;
                // read the bytes from the socket
                // and convert the case
                while((c = sock.getInputStream().read()) != -1) {
                    if(!connected) {
                        if(c != 0 & trackByteArray < 3) {
                            outputStream.write(c);
                        }
                        else {
                            curEncryptedByteArray = outputStream.toByteArray();
                            outputStream.reset();
                            
                            BigInteger curBigInteger = new BigInteger(curEncryptedByteArray);

                            if (trackByteArray == 0) {
                                String decryptedString = KeyGeneration.decrypt(curBigInteger, serverNed);

                                if (!decryptedString.equals(userInfoArray[7])) {
                                    throw new Exception("Wrong user.");
                                }
                            }
                            else if (trackByteArray == 1) {
                                String decryptedString = KeyGeneration.decrypt(curBigInteger, clientNde);

                                if (!decryptedString.equals(userInfoArray[0])) {
                                    throw new Exception("Wrong company name.");
                                }
                            }
                            else if (trackByteArray == 2) {
                                String decryptedString = KeyGeneration.decrypt(curBigInteger, serverNed);

                                agreedKValue = new BigInteger(decryptedString);
                                agreedKValueBytes = agreedKValue.toByteArray();

                                connected = true;
                            }
                            trackByteArray++;
                        }
                    }

                    else {
                        byteNumber++;
                        outputStream.write(c);
                        if (byteNumber % packetLength == 0){
                            lockedCurPacket = outputStream.toByteArray();
                            outputStream.reset();
                            
                            byte[] unlockedCurPacket = OneTimeKey.xorOperation(agreedKValueBytes, lockedCurPacket);
                            byte[] actualData = new byte[Integer.parseInt(userInfoArray[1])];
                            byte[] checkSum = new byte[Integer.parseInt(userInfoArray[2])];
                            
                            int dataPacketCount = 0;
                            for (int i = 0; i < unlockedCurPacket.length; i++) {
                                if (i == 0) {
                                    dataPacketCount = (int) unlockedCurPacket[i];
                                    actualData = new byte[dataPacketCount];
                                }
                                else if (i <= dataPacketCount) {
                                    actualData[i-1] = unlockedCurPacket[i];
                                }
                                else if (i > Integer.parseInt(userInfoArray[1])) {
                                    checkSum[i - Integer.parseInt(userInfoArray[1]) - 1] = unlockedCurPacket[i];
                                }
                            }

                            String dataString = new String(actualData);
                            byte[][] hashCheckArrayArray = Hash.assemble(dataString, Integer.parseInt(userInfoArray[1]), 
                                Integer.parseInt(userInfoArray[2]), Integer.parseInt(userInfoArray[4]), 
                                Integer.parseInt(userInfoArray[3]));

                            //compare checksum
                            for (int z = 0; z < checkSum.length ; z++) {
                                if (hashCheckArrayArray[0][(z+1+Integer.parseInt(userInfoArray[1]))] != checkSum[z]) {
                                    throw new Exception("checksum doesn't match.");
                                }
                            }

                            //uppercase/lowercase switch
                            for (int v=0; v < actualData.length; v++) {
                                if (actualData[v] >= 97 && actualData[v] <= 122) {
                                    actualData[v] -= 32;
                                }
                                else if (actualData[v] >= 65 && actualData[v] <= 90) {
                                    actualData[v] += 32;
                                }
                            }

                            String sendBackString = new String(actualData);

                            byte[][] sendBackArrayArray = Hash.assemble(sendBackString, Integer.parseInt(userInfoArray[1]), 
                                Integer.parseInt(userInfoArray[2]), Integer.parseInt(userInfoArray[4]), 
                                Integer.parseInt(userInfoArray[3]));

                            byte[] sendBackArray = new byte[sendBackArrayArray[0].length*sendBackArrayArray.length];

                            for (int u=0; u < sendBackArrayArray.length; u++) {
                                for (int v=0; v < sendBackArrayArray[u].length; v++) {
                                sendBackArray[(u*sendBackArrayArray[u].length+v)] = sendBackArrayArray[u][v];
                                }
                            }

                            byte[] transferBackData = OneTimeKey.xorOperation(agreedKValueBytes, sendBackArray);

                            sock.getOutputStream().write(transferBackData);
                            
                            if (sock.getInputStream().available() == 0) {
                                sock.getOutputStream().flush();
                            }
                        }
                    }
                }

                Thread.sleep(1000);
                sock.getOutputStream().flush();
                sock.close();
                System.out.println("disconnect...");
            } catch (Exception e) {
                System.out.println("HANDLER: " + e);
            }
        } 
    }

    public void run() {
        while(true) {
            try {
              
              // accept a connection and run handler in a new thread
                new Thread(new RequestHandler(s.accept())).run();
            } catch(Exception e) {
            System.out.println("SERVER: " + e);
            }
        }    
    } 


    public static void main(String[] argv) throws Exception {
        if (argv.length != 3) {
          System.out.println("java SimpleServer <port> <private key text file> <user text file>");
          System.exit(1);
        }

        new SimpleServer(Integer.parseInt(argv[0]), argv[1], argv[2]).run();
    }
}
