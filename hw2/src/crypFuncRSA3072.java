import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class crypFuncRSA3072 {
  public static void main(String[] args) throws Exception {
    
	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
   
    generator.initialize(3072);
    long startK = System.nanoTime();
    KeyPair pair = generator.generateKeyPair();
    long endK = System.nanoTime();
    System.out.println("Key Generation for 3072-bit RSA algorithm " + (endK - startK)+" ns");
    Key pubKey = pair.getPublic();

    Key privKey = pair.getPrivate();
    
    
    File smallinputFile = new File("smallFile.txt");
    File largeinputFile = new File("largeFile.txt");
    File encryptedFileS = new File("textS.encrypted");
    File decryptedFileS = new File("decrypted-textS.txt");
    File encryptedFileL = new File("textL.encrypted");
    File decryptedFileL = new File("decrypted-textL.txt");
    
    
    FileOutputStream out = new FileOutputStream(encryptedFileS); 
    FileOutputStream outD = new FileOutputStream(decryptedFileS); 
    System.out.println("Small 1KB file operations");
    long time1 =encrypdecryp(smallinputFile,out,outD,privKey,pubKey);
    System.out.println("Per Byte Speed "+ (float) encryptedFileS.length()/time1+" byte/ns");
   
    FileOutputStream outL = new FileOutputStream(encryptedFileL); 
    FileOutputStream outDL = new FileOutputStream(decryptedFileL); 	
    System.out.println("Large 10MB file operations");
    long time2 = encrypdecryp(largeinputFile,outL,outDL,privKey,pubKey);
    System.out.println("Per Byte Speed "+ (float) encryptedFileL.length()/time2+" byte/ns");
    
  }
    static long encrypdecryp(File input, FileOutputStream out, FileOutputStream outD, Key privKey, Key pubKey) throws FileNotFoundException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    FileInputStream raw = new FileInputStream(input);
	try {
	Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
	SecureRandom random = new SecureRandom();
    cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
    Cipher cipherD = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
    cipherD.init(Cipher.DECRYPT_MODE, privKey);
    byte[] ibuf = new byte[214]; 
    int len;
    long encryptionTime=0, decryptionTime=0;
	  
    while ((len = raw.read(ibuf)) != -1) {
      long startE = System.nanoTime();
  	  byte[] obuf = cipher.doFinal(ibuf);
	  long endE = System.nanoTime();
	  encryptionTime+=endE-startE;
	  out.write(obuf);
	  long startD = System.nanoTime();
	  byte[] obufD = cipherD.doFinal(obuf);
	  long endD = System.nanoTime();
	  decryptionTime+=endD-startD;
	  outD.write(obufD);    	
    }
	
  System.out.println("Encryption took "+ encryptionTime+" ns");
  System.out.println("Per Byte Speed "+ (float) input.length()/encryptionTime+" byte/ns");
  System.out.println("Decryption took "+ decryptionTime+" ns");
  raw.close();
  out.close();
   outD.close(); 
   return decryptionTime;
	} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException | BadPaddingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return 0;
 
   
  }
}