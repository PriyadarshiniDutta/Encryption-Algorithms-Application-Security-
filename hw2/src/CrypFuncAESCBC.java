import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class CrypFuncAESCBC {
	
 public static void main(String[] args) throws NoSuchAlgorithmException {
	
     File smallinputFile = new File("smallFile.txt");
     File largeinputFile = new File("largeFile.txt");
     File encryptedFileS = new File("textS.encrypted");
     File decryptedFileS = new File("decrypted-textS.txt");
     File encryptedFileL = new File("textL.encrypted");
     File decryptedFileL = new File("decrypted-textL.txt");
	
try {
	//a) AES CBC Mode
	//Key Generation Call
	SecretKey key =CrypFuncAESCBC.keyGeneration("AES",256);
	System.out.println("Small 1KB File");
    //Encryption small 1KB file 
	CrypFuncAESCBC.encryption(key, smallinputFile, encryptedFileS);
    //Decryption small 1KB file 
	CrypFuncAESCBC.decryption(key, encryptedFileS, decryptedFileS);
	System.out.println("Large 10MB File");
	//Encryption large 10MB file 
    CrypFuncAESCBC.encryption(key, largeinputFile, encryptedFileL);
	//Decryption small 10MB file 
    CrypFuncAESCBC.decryption(key, encryptedFileL, decryptedFileL);
	
   
} catch (Exception ex) {
    System.out.println(ex.getMessage());
        ex.printStackTrace();
}
}

static SecretKey keyGeneration(String algorithm, int size) throws NoSuchAlgorithmException
 {   
    
	 KeyGenerator gen = KeyGenerator.getInstance(algorithm);
	 gen.init(size); 
	 // starting time 
     long start = System.nanoTime();
	 SecretKey secretKey = gen.generateKey();
	 long end = System.nanoTime();
	 
     System.out.println("Key Generation for "+ algorithm+" "+size+" takes " + (end - start)+" ns");
	 
	 return secretKey;
 }
 static void encryption(SecretKey secretKey,File inputFile,File encryptedFile) 
 {
	 
   try {
     Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
     String initVector="encryptionIntVec";
     IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
     cipher.init(Cipher.ENCRYPT_MODE, secretKey,iv);      
     
     FileInputStream inputStream = new FileInputStream(inputFile);
     byte[] inputBytes = new byte[(int) inputFile.length()];
     inputStream.read(inputBytes); 
     // starting time 
     long start = System.nanoTime();
     byte[] outputBytes = cipher.doFinal(inputBytes);
     long end = System.nanoTime();
     FileOutputStream outputStream = new FileOutputStream(encryptedFile);
     outputStream.write(outputBytes);
	
	 
     System.out.println("Encryption in AES CBC mode takes "+ (end - start)+" ns");
     System.out.println("Per Byte Speed "+ (float) inputFile.length()/(end-start)+" byte/ns");

     inputStream.close();
     outputStream.close();
      
   }catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException| IllegalBlockSizeException | IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
       e.printStackTrace();
   }
 }
 static void decryption(SecretKey secretKey, File encryptedFile, File decryptedFile) 
 {
	   try {
		     Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		     String initVector="decryptionIntVec";
		     IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
		     cipher.init(Cipher.DECRYPT_MODE, secretKey,iv);      
		     
		     FileInputStream inputStream = new FileInputStream(encryptedFile);
		     byte[] inputBytes = new byte[(int) encryptedFile.length()];
		     inputStream.read(inputBytes);     
		     // starting time 
		     long start = System.nanoTime();
		     byte[] outputBytes = cipher.doFinal(inputBytes);
		     long end = System.nanoTime();
		     FileOutputStream outputStream = new FileOutputStream(decryptedFile);
		     outputStream.write(outputBytes);
			 
			 
		     System.out.println("Decryption in AES CBC mode takes "+ (end - start)+" ns");
		     System.out.println("Per Byte Speed "+ (float) encryptedFile.length()/(end-start)+" byte/ns");

		     inputStream.close();
		     outputStream.close();
		      
		   }catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException| IllegalBlockSizeException | IOException | InvalidKeyException | InvalidAlgorithmParameterException e) {
		       e.printStackTrace();
		   }
	
}
 
}