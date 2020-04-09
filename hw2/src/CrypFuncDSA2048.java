import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;


public class CrypFuncDSA2048 {
   public static void main(String args[]) throws Exception{
	   
	  File smallinputFile = new File("smallFile.txt");
	  File largeinputFile = new File("largeFile.txt");
     
      KeyPairGenerator key = KeyPairGenerator.getInstance("DSA");
      key.initialize(2048);
      // starting time 
      long startk = System.nanoTime();
      //Generate the pair of keys
      KeyPair pair = key.generateKeyPair();
      long endk = System.nanoTime();
      System.out.println("Key Generation in DSA 2048-bit key "+ (endk - startk)+" ns");
      PrivateKey privKey = pair.getPrivate();
      //Creating a Signature object
      Signature sign = Signature.getInstance("SHA256withDSA");
      //Initializing the signature
      sign.initSign(privKey);
      
      //Small 1KB file signing and verification
      FileInputStream inputStream = new FileInputStream(smallinputFile);
      byte[] inputBytes = new byte[(int) smallinputFile.length()];
      inputStream.read(inputBytes); 
      //Adding data to the signature
      sign.update(inputBytes);
      // starting time 
      long starts = System.nanoTime();
      //Calculating the signature
      byte[] signature = sign.sign(); 
      long ends = System.nanoTime();
      System.out.println("Time to produce a signature for 1KB small file "+ (ends - starts)+" ns");
      System.out.println("Per Byte Speed "+ (float) smallinputFile.length()/(ends - starts)+" byte/ns");
      //Initializing the signature
      sign.initVerify(pair.getPublic());
      sign.update(inputBytes);
      // starting time 
      long startv = System.nanoTime();
      //Verifying the signature
      boolean verification = sign.verify(signature);  
      long endv = System.nanoTime();
      System.out.println("Time to verify for 1KB small file "+ (endv - startv)+" ns");
      System.out.println("Per Byte Speed "+ (float) smallinputFile.length()/(ends - starts)+" byte/ns");
      
      if(verification) {
         System.out.println("Signature verified");   
      } else {
         System.out.println("Signature failed");
      }
      
    //Large 10MB file signing and verification
    //Initializing the signature
      sign.initSign(privKey);
      FileInputStream inputStream2 = new FileInputStream(largeinputFile);
      byte[] inputBytes2 = new byte[(int) largeinputFile.length()];
      inputStream2.read(inputBytes2); 
      //Adding data to the signature
      sign.update(inputBytes2); 
   // starting time 
      long startl = System.nanoTime();
      //Calculating the signature
      byte[] signature2 = sign.sign();  
      long endl = System.nanoTime();
      System.out.println("Time to produce a signature for 10MB large file "+ (endl - startl)+" ns");
      System.out.println("Per Byte Speed "+ (float) largeinputFile.length()/(endl - startl)+" byte/ns");
      
      //Initializing the signature
      sign.initVerify(pair.getPublic());
      sign.update(inputBytes2);
      // starting time 
      long startvl = System.nanoTime();
      //Verifying the signature
      boolean verification2 = sign.verify(signature2);   
      long endvl = System.nanoTime();
      System.out.println("Time to verify a signature for 10MB large file "+ (endvl - startvl)+" ns");
      System.out.println("Per Byte Speed "+ (float) largeinputFile.length()/(endl - startl)+" byte/ns");
      if(verification2) {
         System.out.println("Signature verified");   
      } else {
         System.out.println("Signature failed");
      }
      
      inputStream.close();
      inputStream2.close();
      
   }
}