import java.math.BigInteger;
import java.util.Random;
import java.util.ArrayList;
import java.lang.Math;

public class OneTimeKey {
	public static void main(String[] argv) throws Exception {
		if (argv.length != 2) {
			System.out.println("OneTimeKey <key> <data>");
			System.exit(1);
		}

		byte[] key = argv[0].getBytes();
		byte[] data = argv[1].getBytes();

		byte[] xorResult = new byte[data.length];
		xorResult = xorOperation(key, data);
		String encrypted = new String(xorResult);

		byte[] xorResultResult = new byte[data.length];
		xorResultResult = xorOperation(key, xorResult);
		String decrypted = new String(xorResultResult);


		System.out.println();
		System.out.println("encrypted:");
		System.out.println(encrypted);
		System.out.println();
		System.out.println("decrypted:");
		System.out.println(decrypted);
	}

	public static byte[] xorOperation(byte[] key, byte[] data) {
        if (data.length % key.length != 0) {
            throw new RuntimeException("data length must be divisible by key length!");
        }

		byte[] resultBytes = new byte[data.length];

		for (int i=0; i < data.length; i++) {
			int xorVal  = key[i%key.length] ^ data[i];
			resultBytes[i] = (byte) xorVal;
		}
		
		return resultBytes;
	}

	public static BigInteger generateKey(int divisibleNo) {
		ArrayList<Integer> potentialLengths = new ArrayList<Integer>();

		for (int i = 1; i <= divisibleNo/2; i++) {
			if (divisibleNo%i == 0 && i < 10) {
				potentialLengths.add(i);
			}
		}

		Random r = new Random();
		int chosenNumber = potentialLengths.get(r.nextInt(potentialLengths.size()));
		
		byte[] byteNum = new byte[chosenNumber];

		for (int i=0; i < chosenNumber; i++) {
			int x = r.nextInt(215 - 8) + 8;
			byteNum[i] = (byte) x;
		}

		BigInteger result = new BigInteger(byteNum);
		BigInteger zero = new BigInteger("0");
		BigInteger negativeOne = new BigInteger("-1");

		if (result.compareTo(zero) == -1){
			result = result.multiply(negativeOne);
		}
		
		return result;
	}
}