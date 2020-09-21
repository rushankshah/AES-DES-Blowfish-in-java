package com.learning.goodquestions;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishCryptography {
	Cipher cipher = null;
	private static SecretKey secretKey;
    private static byte[] key;
	public static void setKey(String myKey) 
    {
        try {
            key = myKey.getBytes("UTF-8");
            key = Arrays.copyOf(key, 8); 
            secretKey = new SecretKeySpec(key, "Blowfish");
        } 
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
	public BlowfishCryptography(String myKey) {
		try {
			setKey(myKey);
			cipher = Cipher.getInstance("Blowfish");
		} catch (NoSuchPaddingException ex) {
			System.out.println(ex);
		} catch (NoSuchAlgorithmException ex) {
			System.out.println(ex);
		}

	}

	public byte[] encryptText(String plainText) {
		byte[] cipherBytes = null;
		try {
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] plainBytes = plainText.getBytes();
			cipherBytes = cipher.doFinal(plainBytes);
		} catch (IllegalBlockSizeException ex) {
			System.out.println(ex);
		} catch (BadPaddingException ex) {
			System.out.println(ex);
		} catch (InvalidKeyException ex) {
			System.out.println(ex);
		}

		return cipherBytes;
	}

	public String decryptText(byte[] cipherBytes) {
		String plainText = null;
		try {
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] plainBytes = cipher.doFinal(cipherBytes);
			plainText = new String(plainBytes);
		} catch (IllegalBlockSizeException ex) {
			System.out.println(ex);
		} catch (BadPaddingException ex) {
			System.out.println(ex);
		} catch (InvalidKeyException ex) {
			System.out.println(ex);
		}

		return plainText;
	}

	public String encrypt(String plainText) {
		String cipherText = null;
		byte[] cipherBytes = encryptText(plainText);
		cipherText = bytesToString(cipherBytes);
		return cipherText;
	}

	public String decrypt(String cipherText) {
		String plainText = null;
		byte[] cipherBytes = stringToBytes(cipherText);
		plainText = decryptText(cipherBytes);
		return plainText;
	}

	public static void main(String[] args) {
		String key = "thisisakey";
		BlowfishCryptography blowfishAlgorithm = new BlowfishCryptography(key);
		String plainText = "MynameisRushank";
		System.out.println("Plain text: " + plainText);
		long timeBeforeEncryption = System.nanoTime();
		String cipherText = blowfishAlgorithm.encrypt(plainText);
		long timeAfterEncryption = System.nanoTime();
		long encryptionTime = timeAfterEncryption - timeBeforeEncryption;
		System.out.println("Encrypted message in Blowfish: " + cipherText);
		System.out.println("Time taken for encryption: "+encryptionTime);
		long timeBeforeDecryption = System.nanoTime();
		String decryptedText = blowfishAlgorithm.decrypt(cipherText);
		long timeAfterDecryption = System.nanoTime();
		long decryptionTime = timeAfterDecryption - timeBeforeDecryption;
		System.out.println("Decrypted message in Blowfish: " + decryptedText);
		System.out.println("Time taken for decryption: "+decryptionTime);
	}

	private String bytesToString(byte[] rawText) {
        String plainText = null;
        plainText = Base64.getEncoder().encodeToString(rawText);
        return plainText;
    }

	private byte[] stringToBytes(String plainText) {
		byte[] rawText = null;
		rawText = Base64.getDecoder().decode(plainText);
		return rawText;
	}
}
