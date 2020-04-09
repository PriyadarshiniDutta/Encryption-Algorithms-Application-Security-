
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import org.bouncycastle.jcajce.provider.digest.SHA3;



public class HashSHA {
	
	public static void main(String[] args) {
	
	//File smallinputFile = new FileInputStream("smallFile.txt");
	//File largeinputFile = new FileInputStream("largeFile.txt");
	
	try {
		//SHA - 256 small File
		byte[] smallb = Files.readAllBytes(Paths.get("smallFile.txt"));
		byte[] largeb = Files.readAllBytes(Paths.get("largeFile.txt"));
		long time1,time2,time3,time4,time5,time6;
		time1=hashFunction(smallb,"SHA-256");
	    System.out.println("Hashing for 1kb file SHA-256 takes "+ time1+" ns");
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time1+" byte/ns");
		time2=hashFunction(largeb,"SHA-256");	 
	    System.out.println("Hashing for 10MB file SHA-256 takes "+ time2+" ns");	 
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time2+" byte/ns");
		time3=hashFunction(smallb,"SHA-512");
	    System.out.println("Hashing for 1kb file SHA-512 takes "+ time3+" ns");
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time3+" byte/ns");
		time4=hashFunction(largeb,"SHA-512");	 
	    System.out.println("Hashing for 10MB file SHA-512 takes "+ time4+" ns");
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time4+" byte/ns");
		time5=hashFunction(smallb,"SHA3_256");
	    System.out.println("Hashing for 1kb file SHA3_256 takes "+ time5+" ns");
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time5+" byte/ns");
		time6=hashFunction(largeb,"SHA3_256");	 
	    System.out.println("Hashing for 10MB file SHA3_256 takes "+ time6+" ns");
	    System.out.println("Per Byte Speed "+ (float) Paths.get("smallFile.txt").toFile().length()/time6+" byte/ns");
		
	    
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
}
	
	static long hashFunction(byte[] inputFile,String version)
	{
		long start = 0, end = 0;
		try
		{
			if (version.equals("SHA3_256"))
            {
				SHA3.DigestSHA3 sha3 = new SHA3.DigestSHA3(256);
				start = System.nanoTime();
				sha3.update(inputFile);		
				byte[] smallhash =sha3.digest();
		        end = System.nanoTime();
		        return (end - start);
            }
	    start = System.nanoTime();
		byte[] smallhash = MessageDigest.getInstance(version).digest(inputFile);
		end = System.nanoTime();		
	
		}
		catch(Exception ex)
		{
			 ex.printStackTrace();
		}
		return (end - start);
	}
	
}

    
	


