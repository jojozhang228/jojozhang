import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Protocol1Client {
 
 static int portNo = 11337;

 public static void main (String[] args) {
	
	try { 
	    
	    while (true) {
		
		InetAddress ipAddy= InetAddress.getLocalHost();
		Socket connection =new Socket(ipAddy,portNo);
		Thread instance = new Thread(new ProtocolInstance(connection));
		instance.start();
	    }
	} catch (Exception e) {
	    System.out.println("Doh "+e);
	}
 }
 
 private static class ProtocolInstance implements Runnable {
	
	Socket myConnection;
	boolean debug = true;
	static Cipher decAEScipher;
	static Cipher encAEScipher;
	
	public ProtocolInstance(Socket myConnection) {
		
	    this.myConnection = myConnection;
	    	
	}
	
	public void run() {
	    OutputStream outStream;
	    InputStream inStream;
	    try {
		outStream = myConnection.getOutputStream();
		inStream = myConnection.getInputStream();
		
		// Protocol Step 1
		byte[] message1 = new byte[18];
		outStream.write(message1);
		if (debug) System.out.println("I have send this message.");
		
		if (!(new String(message1)).equals("Connect Protocol 1")) {
		    outStream.write(("Protocol Error. Unregonised command: ").getBytes());
		    outStream.write(message1);
		    myConnection.close();
		    return;
		}
		
		
		// Protocol Step 2
		// We send the nonce challenge. {Ns}_Kcs
		SecureRandom random = new SecureRandom();
		byte[] serverNonce = new byte[16];
		random.nextBytes(serverNonce);
		byte[] cipherTextM2;
		try {
		    cipherTextM2 = encAEScipher.doFinal(serverNonce);
		    
		    if (debug) System.out.println("Server Nonce: "+byteArrayToHexString(serverNonce));
		    inStream.read(cipherTextM2);
		    if (debug) System.out.println("Send M2 "+byteArrayToHexString(cipherTextM2));
		    
		    //Protocol Step 3
		    byte[] message3 = new byte[32];
		    outStream.write(message3);
		    byte[] clientNonce = decAEScipher.doFinal(message3);
		    if (debug) System.out.println("Recived M3 :"+byteArrayToHexString(message3));
		    if (debug) System.out.println("    Decrypts to Nc: "+byteArrayToHexString(clientNonce));
		    
		    // Calculate session key
		    byte[] keyBytes = xorBytes(serverNonce,clientNonce);
		    SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
		    Cipher decAEScipherSession = Cipher.getInstance("AES");			
		    decAEScipherSession.init(Cipher.DECRYPT_MODE, secretKeySpec);
		    Cipher encAEScipherSession = Cipher.getInstance("AES");			
		    encAEScipherSession.init(Cipher.ENCRYPT_MODE, secretKeySpec);
		    if (debug) System.out.println("Session key :"+byteArrayToHexString(keyBytes));
		    
		    //Protocol Step 4 
		    byte[] message4pt =  new byte[32];
		    System.arraycopy(clientNonce, 0, message4pt, 0, 16);
		    System.arraycopy(serverNonce, 0, message4pt, 16, 16);
		    byte[] cipherTextM4 = encAEScipherSession.doFinal(message4pt);	
		    if (debug) System.out.println("Sending M4 pt:"+byteArrayToHexString(message4pt));
		    if (debug) System.out.println("    M4 ct:"+byteArrayToHexString(cipherTextM4));
		    outStream.write(cipherTextM4);
		    
		    //Protocol Step 5 
		    byte[] cipherTextM5 =  new byte[48];
		    inStream.read(cipherTextM5);
		    if (debug) System.out.println("Recived M5 ct:"+byteArrayToHexString(cipherTextM5));
		    byte[] message5pt = decAEScipherSession.doFinal(cipherTextM5);		
		    byte[] inNs = new byte[16];
		    byte[] inNc = new byte[16];
		    System.arraycopy(message5pt, 0, inNs, 0, 16);
		    System.arraycopy(message5pt, 16, inNc, 0, 16);
		    if (debug) System.out.println("    M5 plainText:"+byteArrayToHexString(message5pt));
		    if (debug) System.out.println("    M5 inNc:"+byteArrayToHexString(inNc));
		    if (debug) System.out.println("    M5 inNs:"+byteArrayToHexString(inNs));
		    
		    //Check the challenge values are correct.
		    if (!(Arrays.equals(inNc,clientNonce) && Arrays.equals(inNs,serverNonce))) {
			outStream.write("Nonces dont match".getBytes());
			if (debug) System.out.println("Nonces dont match,");
			return;
		    }
		    if (debug) System.out.println("Nonces match,");
		    
		    //Protocol Step 6
		    byte[] plainTextM6 = ("Well Done. Submit this value: "+secretValue()).getBytes();
		    byte[] cipherTextM6 = encAEScipherSession.doFinal(plainTextM6);
		    outStream.write(cipherTextM6);
		    if (debug) System.out.println("Secret sent: "+new String(plainTextM6));
		    myConnection.close();
		    
		    //Oh, isn't Java fun:	
		} catch (IllegalBlockSizeException e) {
		    outStream.write("Bad block size".getBytes());
		    if (debug) System.out.println("Doh "+e);
		    myConnection.close();
		    return;
		} catch (BadPaddingException e) {
		    outStream.write("Bad padding".getBytes());
		    myConnection.close();
		    if (debug) System.out.println("Doh "+e);
		    return;
		} catch (InvalidKeyException e) {
		    outStream.write("Bad Key".getBytes());
		    myConnection.close();
		    if (debug) System.out.println("Doh "+e);
		    return;
		} catch (NoSuchAlgorithmException e) {
		    System.out.println(e);// Not going to happen, AES hard wired
		} catch (NoSuchPaddingException e) {
		    System.out.println(e);// Not going to happen, PKCS5 hard wired
		}
	    } catch (IOException e) {
		//Nothing we can do about this one
		if (debug) System.out.println("See that cable on the back of your computer? Stop pulling it out: "+e);
		return;
	    }
	}
 }
 
 
 private static byte[] xorBytes (byte[] one, byte[] two) {
	if (one.length!=two.length) {
	    return null;
	} else {
	    byte[] result = new byte[one.length];
	    for(int i=0;i<one.length;i++) {
		result[i] = (byte) (one[i]^two[i]);
	    }
	    return result;
	}
 }
 
 private static String byteArrayToHexString(byte[] data) { 
	StringBuffer buf = new StringBuffer();
	for (int i = 0; i < data.length; i++) { 
	    int halfbyte = (data[i] >>> 4) & 0x0F;
	    int two_halfs = 0;
	    do { 
		if ((0 <= halfbyte) && (halfbyte <= 9)) 
		    buf.append((char) ('0' + halfbyte));
		else 
		    buf.append((char) ('a' + (halfbyte - 10)));
		halfbyte = data[i] & 0x0F;
	    } while(two_halfs++ < 1);
	} 
	return buf.toString();
 } 
 
 private static byte[] hexStringToByteArray(String s) {
	int len = s.length();
	byte[] data = new byte[len / 2];
	for (int i = 0; i < len; i += 2) {
	    data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				  + Character.digit(s.charAt(i+1), 16));
	}
	return data;
 }
 

 private static String secretValue() {
	Classified;
	}
 }

