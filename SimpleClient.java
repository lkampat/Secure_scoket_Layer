import java.net.Socket;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Files;
import java.io.ByteArrayOutputStream;

public class SimpleClient { 

    // network socket
    private Socket s;
    private BigInteger[] encryptedInfoArray = new BigInteger[3];
    private byte[] completeEncryptedByteArray;
    private BigInteger generatedKey;
    private String[] myInfoArray = new String[7];

    public SimpleClient(String host, int port, String myInfoFileName) throws Exception {
        // open a connection to the server
        s = new Socket(host,port);

        String userName = myInfoFileName.replace(".txt", "");

        Path pathMyInfoFileName = Path.of(myInfoFileName);
        String myInfo = Files.readString(pathMyInfoFileName);
        String[] tempMyInfoArray = myInfo.split("\n");

        String privateKeyD = tempMyInfoArray[0].split(",")[0];
        privateKeyD = privateKeyD.replaceAll("\\D+","");
        String publicN = tempMyInfoArray[0].substring(tempMyInfoArray[0].lastIndexOf(",") + 1);
        publicN = publicN.replaceAll("\\D+","");
        BigInteger[] clientKR = new BigInteger[2];
        clientKR[0] = new BigInteger(privateKeyD);
        clientKR[1] = new BigInteger(publicN);

        //my info array: [company name, ndatabytes, ncheckbytes, k, pattern, serverE, serverN]
        for (int i=1; i <tempMyInfoArray.length; i++) {
            myInfoArray[i-1] = tempMyInfoArray[i].substring(tempMyInfoArray[i].lastIndexOf("=") + 1);
        }
        myInfoArray[5] = tempMyInfoArray[6].split(",")[0];
        myInfoArray[5] = myInfoArray[5].replaceAll("\\D+","");
        myInfoArray[6] = tempMyInfoArray[6].substring(tempMyInfoArray[6].lastIndexOf(",") + 1).replaceAll("\\D+","");

        //encrypted info: 0 is username, 1 is company name, 2 is k value
        BigInteger[] serverNed = new BigInteger[3];
        serverNed[0] = new BigInteger(myInfoArray[6]);
        serverNed[1] = new BigInteger(myInfoArray[5]);
        serverNed[2] = new BigInteger("0");
        BigInteger[] clientNde = new BigInteger[3];
        //Position of d and e had to be swapped for this
        clientNde[0] = clientKR[1];
        clientNde[1] = clientKR[0];
        clientNde[2] = new BigInteger("0");

        generatedKey = OneTimeKey.generateKey(Integer.parseInt(myInfoArray[1]) + Integer.parseInt(myInfoArray[2] + 1));
        String generatedKeyString = generatedKey.toString();
        String testing = "15429";

        encryptedInfoArray[0] = KeyGeneration.encrypt(serverNed, userName);
        encryptedInfoArray[1] = KeyGeneration.encrypt(clientNde, myInfoArray[0]);
        encryptedInfoArray[2] = KeyGeneration.encrypt(serverNed, generatedKeyString);

        byte[] userNameEncryptedByteArray = encryptedInfoArray[0].toByteArray();
        byte[] companyNameEncryptedByteArray = encryptedInfoArray[1].toByteArray();
        byte[] kValueEncryptedByteArray = encryptedInfoArray[2].toByteArray();
        
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(userNameEncryptedByteArray);
            outputStream.write(0);
            outputStream.write(companyNameEncryptedByteArray);
            outputStream.write(0);
            outputStream.write(kValueEncryptedByteArray);
            outputStream.write(0);

        completeEncryptedByteArray = outputStream.toByteArray();

        // for (byte check: completeEncryptedByteArray) System.out.println(check);
    }

    // data transfer
    public void execute() throws Exception {
        int c, k=0,i=0;
        int byteNumber = 0;
        byte[] lockedCurPacket;  
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        int packetLength = Integer.parseInt(myInfoArray[1]) + Integer.parseInt(myInfoArray[2]) + 1;

        s.getOutputStream().write(completeEncryptedByteArray);
        s.getOutputStream().flush();

        // read data from keyboard until end of file
        while((c = System.in.read()) != -1) {
            byteOutputStream.write(c);
            ++k;
        }

        byte[] preHashedAndXoredBytes = byteOutputStream.toByteArray();
        String hashedAndXoredString = new String(preHashedAndXoredBytes);
        int intNDatabytes = Integer.parseInt(myInfoArray[1]);
        int intNCheckbytes = Integer.parseInt(myInfoArray[2]);
        int intPattern = Integer.parseInt(myInfoArray[4]);
        int intK = Integer.parseInt(myInfoArray[3]);
        byte[][] byteArrayArray = Hash.assemble(hashedAndXoredString, intNDatabytes, intNCheckbytes, intPattern, intK);
        byte[] dataByteArray = new byte[byteArrayArray[0].length*byteArrayArray.length];
        for (int u=0; u < byteArrayArray.length; u++) {
            for (int v=0; v < byteArrayArray[u].length; v++) {
                dataByteArray[(u*byteArrayArray[u].length+v)] = byteArrayArray[u][v];
            }
        }

        byte[] generatedKeyBytes = generatedKey.toByteArray();        
        byte[] dataToTransfer = OneTimeKey.xorOperation(generatedKeyBytes, dataByteArray);


        s.getOutputStream().write(dataToTransfer);

        Thread.sleep(1000);
        // read until end of file or same number of characters
        // read from server
        byteOutputStream.reset(); 
        while((c = s.getInputStream().read()) != -1) {
            byteNumber++;
            byteOutputStream.write(c);
            if (byteNumber % packetLength == 0){
                lockedCurPacket = byteOutputStream.toByteArray();
                byteOutputStream.reset();
                
                byte[] unlockedCurPacket = OneTimeKey.xorOperation(generatedKeyBytes, lockedCurPacket);
                byte[] actualData = new byte[Integer.parseInt(myInfoArray[1])];
                byte[] checkSum = new byte[Integer.parseInt(myInfoArray[2])];
                
                int dataPacketCount = 0;
                for (int q = 0; q < unlockedCurPacket.length; q++) {
                    if (q == 0) {
                        dataPacketCount = (int) unlockedCurPacket[q];
                        actualData = new byte[dataPacketCount];
                    }
                    else if (q <= dataPacketCount) {
                        actualData[q-1] = unlockedCurPacket[q];
                    }
                    else if (q > Integer.parseInt(myInfoArray[1])) {
                        checkSum[q - Integer.parseInt(myInfoArray[1]) - 1] = unlockedCurPacket[q];
                    }
                }

                String dataString = new String(actualData);
                byte[][] hashCheckArrayArray = Hash.assemble(dataString, Integer.parseInt(myInfoArray[1]), 
                    Integer.parseInt(myInfoArray[2]), Integer.parseInt(myInfoArray[4]), 
                    Integer.parseInt(myInfoArray[3]));

                //compare checksum
                for (int z = 0; z < checkSum.length ; z++) {
                    if (hashCheckArrayArray[0][(z+1+Integer.parseInt(myInfoArray[1]))] != checkSum[z]) {
                        throw new Exception("checksum doesn't match.");
                    }
                }
                System.out.print(dataString);
                
            }
            if (s.getInputStream().available() == 0) break;
        }
        System.out.println();
        System.out.println("wrote " +i + " bytes");
        s.close();
    }

   
    public static void main(String[] argv) throws Exception {
        if (argv.length != 3) {
            System.out.println("java SimpleClient <host> <port> <user text file>");
            System.exit(1);
        }

        String host = argv[0];
        int port = Integer.parseInt(argv[1]);
        String myInfoFileName = argv[2];


        new SimpleClient(host,port, myInfoFileName).execute();
    } 
}
