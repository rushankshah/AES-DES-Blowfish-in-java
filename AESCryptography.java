package com.learning.goodquestions;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
 
public class AESCryptography {
 
    private static SecretKeySpec secretKey;
    private static byte[] key;
 
    public static void setKey(String myKey) 
    {
        try {
            key = myKey.getBytes("UTF-8");
            key = Arrays.copyOf(key, 16); 
            secretKey = new SecretKeySpec(key, "AES");
        } 
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
 
    public static String encrypt(String strToEncrypt) 
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }
 
    public static String decrypt(String strToDecrypt) 
    {
        try
        {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } 
        catch (Exception e) 
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }
    public static void main(String[] args) {
    	final String keyInString = "thisisthekey";
    	setKey(keyInString);
        String plainText = "MynameisRushank";
        System.out.println("Plain text: "+plainText);
        long timeBeforeEncryption = System.nanoTime();
        String encryptedString = AESCryptography.encrypt(plainText) ;
        long timeAfterEncryption = System.nanoTime();
        long encryptionTime = timeAfterEncryption - timeBeforeEncryption;
        long timeBeforeDecryption = System.nanoTime();
        String decryptedString = AESCryptography.decrypt(encryptedString) ;
        long timeAfterDecryption = System.nanoTime();
        long decryptionTime = timeAfterDecryption - timeBeforeDecryption;
        System.out.println("Encrypted message in AES: "+encryptedString);
        System.out.println("Time taken for encryption: "+encryptionTime);
        System.out.println("Decrypted message in AES: "+decryptedString);
        System.out.println("Time taken for decryption: "+decryptionTime);
	}
}
