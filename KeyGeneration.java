import java.math.BigInteger;
import java.util.Random;

public class KeyGeneration {
	public KeyGeneration(String message) {}

    public static void main(String[] argv) throws Exception {
        if (argv.length != 2) {
        	System.out.println("java KeyGeneration <message to encrypt> <prime size>");
        	System.exit(1);
        }

        String plainText = argv[0];
        String primeSize = argv[1];

        int primeSizeInt = Integer.parseInt(primeSize);

        BigInteger[] nED = generateKeys(primeSizeInt);
        System.out.println("KU: {" + nED[1] + ", " + nED[0] + "}");
    	System.out.println("KR: {" + nED[2] + ", " + nED[0] + "}");
        
        BigInteger encryptedDec = encrypt(nED, plainText);
        System.out.println("encrypted: " + encryptedDec);

        String decrypted = decrypt(encryptedDec, nED);
        System.out.println("decrypted: " + decrypted);
	}





	public static BigInteger[] generateKeys(int primeSizeInt) {
        Random randomValue1 = new Random();
        Random randomValue2 = new Random();

        // Values p, q, n, phi(n), e, d
        BigInteger primeP = BigInteger.probablePrime(primeSizeInt, randomValue1);
        BigInteger primeQ = BigInteger.probablePrime(primeSizeInt, randomValue2);
        BigInteger one = new BigInteger("1");
        BigInteger zero = new BigInteger("0");

        BigInteger pMinus1 = primeP.subtract(one);
        BigInteger qMinus1 = primeQ.subtract(one);

        BigInteger n = primeP.multiply(primeQ);
        BigInteger phiOfN = pMinus1.multiply(qMinus1);

        BigInteger e = new BigInteger("50");

        while(phiOfN.gcd(e).compareTo(one) != 0) {
    		e = e.add(one);
        }

        BigInteger d = e.modInverse(phiOfN);

        BigInteger[] nED = new BigInteger[3];
        nED[0] = n;
        nED[1] = e;
        nED[2] = d;

        return nED;
	}





	public static BigInteger encrypt(BigInteger[] nED, String plainText) {
        // Convert message to  BigInteger. Ex: abcd -> 979899100, then encrypt
        String messageToNum = "1";

        for (int i=0; i < plainText.length(); i++) {
        	int charNum = (int) plainText.charAt(i);
        	if (charNum < 10) {
        		messageToNum = messageToNum + 00 + charNum;
        	}
        	else if (charNum < 100) {
        		messageToNum = messageToNum + 0 + charNum;
        	}
        	else {
        		messageToNum = messageToNum + charNum;
        	}
        }

        BigInteger plainTextDec = new BigInteger(messageToNum);

        BigInteger encryptedMessageDec = plainTextDec.modPow(nED[1], nED[0]);

        return encryptedMessageDec;
	}





	public static String decrypt(BigInteger encryptedMessageDec, BigInteger[] nED) {
        // Convert encrypted BigInteger back to plaintext
        BigInteger decryptedMessageDec = encryptedMessageDec.modPow(nED[2], nED[0]);

        String decryptedPlainTextDec = decryptedMessageDec.toString(10);
        String decryptedPlainText = "";

        for (int i=1; i < decryptedPlainTextDec.length(); i = i+3) {
        	String oneCharStringInt = decryptedPlainTextDec.substring(i, i+3);
        	int stringToInt = Integer.parseInt(oneCharStringInt);
        	char intToChar = (char) stringToInt;
        	decryptedPlainText = decryptedPlainText + intToChar;
        }

        return decryptedPlainText;
	}
}