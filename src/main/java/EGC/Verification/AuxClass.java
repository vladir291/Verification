package EGC.Verification;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class AuxClass {
	
	//funcion resumen con md5 (text indica el texto que se le aplicara la función resumen)
	//hay que pasarle el texto, no el atajo
	public static byte[] getHashCodeMD5(String text){
		byte[] resumen = null;
		 MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		  messageDigest.update(text.getBytes());
		  resumen = messageDigest.digest();
		 return resumen;
		
	}
	
	//funcion resumen con SHA-1 (text indica el texto que se le aplicara la función resumen)
	//hay que pasarle el texto, no el atajo
	public static byte[] getHashCodeSHA(String text){
		byte[] resumen = null;
		 MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
		  messageDigest.update(text.getBytes());
		  resumen = messageDigest.digest();
		 return resumen;
	}
	

	
	//funcion para generar clave DES y almacenarla en base de datos
	// guarda el string de la secret key en base de datos
	public static void postKeyDES(String id) throws NoSuchAlgorithmException{
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		String stringclave = Base64.getEncoder().encodeToString(clave.getEncoded()); //convierte la key a string
		DataBaseManager dbm=new DataBaseManager(); // para utulizar metodos de esta clase
		dbm.saveKeyDES(id,stringclave);
		
	}
	
	//genera una clave para DES y la devuelve
	public static SecretKey returnKeyDes(){
		KeyGenerator generadorDES = null;
		try {
			generadorDES = KeyGenerator.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		return clave;
	}
	public static KeyPair returnKeysRSA(){
	KeyPairGenerator keyGen = null;
	try {
		keyGen = KeyPairGenerator.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
    keyGen.initialize(512);  // tamano clave 512 bits
    KeyPair clavesRSA = keyGen.generateKeyPair();
    return clavesRSA;
	}
	
	
	//recuperar clave "string" de la base de datos y devolverla como SecretKey
	public static SecretKey getKeyDES(String id){
		
		DataBaseManager dbm=new DataBaseManager(); // para utulizar metodos de esta clase
		String secretkeystring = dbm.getKeyDES(id);
		//decodificamos de base64
		byte[] decodedKey = Base64.getDecoder().decode(secretkeystring);
		//reconstruimos
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES"); 
		return originalKey;
	}
	// cifrando en des, se le debe pasar el resumen(de una funcion resumen como MD5)
	//como text
	public static byte[] encryptDES(SecretKey key, String text) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// Algoritmo DES
		// Modo : ECB (Electronic Code Book)
		// Relleno : PKCS5Padding
		//inicializo en modo cifrado
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		//paso texto a byte y cifro
		byte[] textocifrado = cifrador.doFinal(text.getBytes());
		return textocifrado;
	}
	// el texto cifrado es la cadena resumen del texto original
	public static String decryptDES(SecretKey key, byte[] textcifrado) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// Algoritmo DES
		// Modo : ECB (Electronic Code Book)
		// Relleno : PKCS5Padding
		//inicializo en modo DEScifrado (QUE CHISTOSO SOY!!)
		cifrador.init(Cipher.DECRYPT_MODE, key);
		//paso cadena byte[] y descifro
		String textodesencriptado = new String(cifrador.doFinal(textcifrado));
		return textodesencriptado;
	}
	
	//cifrado RSA
	public static byte[] encryptRSA(KeyPair keys,String text){
		
		byte[] res = null;
		try {
			Cipher rsa;
			
			PublicKey pubKey = keys.getPublic();
			
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.ENCRYPT_MODE, pubKey);
	    
		
			res = rsa.doFinal(text.getBytes());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			e.printStackTrace();
		} 
		
		return res;
	}
	
	//descifrado RSA
	public static String decryptRSA(KeyPair keys,byte[] cipherText) throws BadPaddingException{
		
		String res = null;
		try {
			Cipher rsa;
			
			PrivateKey privKeyFromBytes = keys.getPrivate();
			
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, privKeyFromBytes);
			
	    
		
			byte[] bytesDesencriptados = rsa.doFinal(cipherText);
		    res = new String(bytesDesencriptados);
		} catch (IllegalBlockSizeException  | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			e.printStackTrace();
		}

		
		return res;
	}
	
	//metodos auxiliares (RSA):
	public static boolean postKeyRSA(String id) {
		boolean success = false;
		try {

			
			 KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			
			 SecureRandom random = SecureRandom.getInstance("SHA1PRNG","SUN");
			 keyGen.initialize(2048, random);
			
			 KeyPair pair = keyGen.generateKeyPair();
			
			 
			 String publicKey = DatatypeConverter.printBase64Binary(pair.getPublic().getEncoded());
			 String privateKey= DatatypeConverter.printBase64Binary(pair.getPrivate().getEncoded());
			 
			 
			 RemoteDataBaseManager rdbm=new RemoteDataBaseManager();
			 if (rdbm.postKeys(id, publicKey, privateKey)){
				 success = true;
			 }
			

		} catch (Exception e) {
			e.printStackTrace();
		}

	
		
		return success;
	}

	
	public static String getPublicKeyRSA(String id) {
		RemoteDataBaseManager rdbm=new RemoteDataBaseManager();
		
		return rdbm.getPublicKey(id);
	}

	
	public static String getPrivateKeyRSA(String id) {

		RemoteDataBaseManager rdbm=new RemoteDataBaseManager();
		
		
		return rdbm.getPrivateKey(id);
	}

	
	public static boolean checkVoteRSA(byte[] votoCifrado, KeyPair key) {
		
		boolean res = true;
		try {
			decryptRSA(key, votoCifrado);
		} catch (BadPaddingException e) {
			res = false;
		}
		return res;

	}
}