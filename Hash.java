import java.math.BigInteger;
import java.lang.Math;

public class Hash {
    public static void main(String[] argv) throws Exception {
        if (argv.length < 5) {
            System.out.println("java Hash <databytes> <checkbytes> <pattern> <k> <text1> <text2> ...");
            System.exit(1);
        }

        int ndatabytes = Integer.parseInt(argv[0]);
        int ncheckbytes = Integer.parseInt(argv[1]);
        int pattern = Integer.parseInt(argv[2]);
        int k = Integer.parseInt(argv[3]);

        for (int i = 4; i < argv.length; i++) {
            byte[][] assembled = assemble(argv[i], ndatabytes, ncheckbytes, pattern, k);
            for (byte[] packedString:assembled) {
                    String byteString = new String(packedString);
                    System.out.println("packed string:");
                    System.out.println(byteString);
            }
        }
    }

    public static byte[][] assemble(String dataString, int ndatabytes, int ncheckbytes, int pattern, int k) {
        if (pattern > 255) {
            throw new RuntimeException("Pattern must be less than 256");
        }

        int eachPacketByteCount = 1 + ndatabytes + ncheckbytes;

        byte[] bytesOfData = dataString.getBytes();
        //how many bytes the data contains
        int countBytesOfData = bytesOfData.length;
        //the amount of padding needed to fill up the last packet
        int paddingNeeded = ndatabytes - (countBytesOfData % ndatabytes);
        if (paddingNeeded == ndatabytes) paddingNeeded = 0;

        //add padding to bytes of data
        byte[] bytesOfDataPadded = new byte[countBytesOfData + paddingNeeded];

        //the number of bytes after data is padded
        int countBytesOfDataPadded = bytesOfDataPadded.length;

        //copy bytes from bytesOfData over
        for (int i=0; i < countBytesOfData; i++) {
            bytesOfDataPadded[i] = bytesOfData[i];
        }

        //add 0s to pad
        if (paddingNeeded > 0) {
            for (int i=countBytesOfData; i < countBytesOfDataPadded; i++) {
                bytesOfDataPadded[i] = (byte) 0;
            }
        }

        //total number of packets that will be created to be transmitted
        int packetsNeeded = countBytesOfDataPadded/ndatabytes;

        //a byte array keeping track of one packet at a time as we iterate through the data bytes
        byte[] curPacket = new byte[eachPacketByteCount];
        if (packetsNeeded == 1) {
            curPacket[0] = (byte) (ndatabytes - paddingNeeded);
        }
        else curPacket[0] = (byte) ndatabytes;

        //an array of packets
        byte[][] allPackets = new byte[packetsNeeded][eachPacketByteCount];
        
        //convert pattern to bytes
        byte patternByte = (byte) pattern;
        
        //keeps track of which packet you're on
        int packetNo = 0;

        //gets the maximum decimal value of checkbytes
        int checkbytesInDec = (int) Math.pow(2, 8*ncheckbytes);
        BigInteger checkbytesInDecBigInt = BigInteger.valueOf(checkbytesInDec);

        //the total value of the checksum
        BigInteger decSumOfData = new BigInteger("0");
        //need to for loop through databytes per packet at a time
        for (int i=0; i < countBytesOfDataPadded; i++) {
            // System.out.println(curPacket[0]);
            byte dataAndPattern = (byte) (patternByte & bytesOfDataPadded[i]);
            int iResidue = i%ndatabytes;

            curPacket[iResidue+1] = bytesOfDataPadded[i];
            //add statement here ending packets and collecting into array of packets

            
            byte[] curByte = new byte[1];
            curByte[0] = dataAndPattern;
            BigInteger curByteBigInt = new BigInteger(curByte);
            decSumOfData = decSumOfData.add(curByteBigInt);

            if (iResidue == ndatabytes-1) {
                //calculate the checksum
                //a lot of conversions required to add checksum to packet

                BigInteger kBigInt = BigInteger.valueOf(k);

                decSumOfData = decSumOfData.multiply(kBigInt);      
                BigInteger checkSum = decSumOfData.mod(checkbytesInDecBigInt);
                byte[] checkSumBytes = checkSum.toByteArray();
                // for (byte abcd: checkSumBytes) System.out.println(abcd);

                int testBytes = ncheckbytes;

                for (int j=(curPacket.length - ncheckbytes); j < curPacket.length; j++) {
                    if (testBytes > checkSumBytes.length) {
                        curPacket[j] = 0;
                        testBytes--;
                    }
                    else {
                        curPacket[j] = checkSumBytes[j - (curPacket.length - testBytes)];
                    }
                }

                allPackets[packetNo] = curPacket;
                packetNo++;

                curPacket = new byte[eachPacketByteCount];
                if (i == (countBytesOfDataPadded - ndatabytes - 1)) {
                    curPacket[0] = (byte) (ndatabytes-paddingNeeded);    
                }
                else curPacket[0] = (byte) ndatabytes;

                decSumOfData = new BigInteger("0");
            }       
        }

        return allPackets;
    }
}