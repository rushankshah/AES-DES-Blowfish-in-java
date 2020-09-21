import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class DESCryptography {

	private static Cipher encryptionCipher;
	private static Cipher decryptionCipher;
	private static SecretKey secretKey;
	private static byte[] key;

	public static void main(String[] args) {

		try {
			String keyInString = "thisisakey";
			setKey(keyInString);
			encryptionCipher = Cipher.getInstance("DES");
			decryptionCipher = Cipher.getInstance("DES");
			encryptionCipher.init(Cipher.ENCRYPT_MODE, secretKey);
			decryptionCipher.init(Cipher.DECRYPT_MODE, secretKey);
			String plainText = "MynameisRushank";
			System.out.println("Plain text: " + plainText);
			long timeBeforeEncryption = System.nanoTime();
			String encrypted = encrypt(plainText);
			long timeAfterEncryption = System.nanoTime();
			long encryptionTime = timeAfterEncryption - timeBeforeEncryption;
			long timeBeforeDecryption = System.nanoTime();
			String decrypted = decrypt(encrypted);
			long timeAfterDecryption = System.nanoTime();
			long decryptionTime = timeAfterDecryption - timeBeforeDecryption;
			System.out.println("Encrypted message in DES: " + encrypted);
			System.out.println("Time taken for Encryption: " + encryptionTime);
			System.out.println("Decrypted message in DES: " + decrypted);
			System.out.println("Time taken for decryption: " + decryptionTime);
		} catch (NoSuchAlgorithmException e) {
			System.out.println("No Such Algorithm:" + e.getMessage());
			return;
		} catch (NoSuchPaddingException e) {
			System.out.println("No Such Padding:" + e.getMessage());
			return;
		} catch (InvalidKeyException e) {
			System.out.println("Invalid Key:" + e.getMessage());
			return;
		}

	}

	public static void setKey(String myKey) {
		try {
			key = myKey.getBytes("UTF-8");
			key = Arrays.copyOf(key, 8);
			secretKey = new SecretKeySpec(key, "DES");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
	}

	public static String encrypt(String str) {
		try {
			byte[] utf8 = str.getBytes("UTF8");
			byte[] enc = encryptionCipher.doFinal(utf8);
			enc = Base64.getEncoder().encode(enc);
			return new String(enc);
		}

		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String decrypt(String str) {
		try {
			byte[] dec = Base64.getDecoder().decode(str.getBytes());
			byte[] utf8 = decryptionCipher.doFinal(dec);
			return new String(utf8, "UTF8");
		}

		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}