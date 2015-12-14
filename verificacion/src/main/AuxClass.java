package main;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
	
	//funcion resumen con md5 (text indica el texto que se le aplicara la funci�n resumen)
	//hay que pasarle el texto, no el atajo
	public byte[] getHashCodeMD5(String text) throws IOException, NoSuchAlgorithmException{
		/* Crear funcion resumen */
		MessageDigest md = MessageDigest.getInstance("MD5"); // Usa MD5
		/* Leer fichero de 1k en 1k y pasar fragmentos leidos a la funcion resumen */
		byte[] buffer = new byte[1000];
		FileInputStream in = new FileInputStream(text);
		int leidos = in.read(buffer, 0, 1000);
		while (leidos != -1) {
			md.update(buffer, 0 , leidos); // Pasa texto claro a la funcion resumen
			leidos = in.read(buffer, 0, 1000);
		}
		in.close();
			
		byte[] resumen = md.digest(); // Completar el resumen
		return resumen;
		
	}
	
	//funcion resumen con SHA-1 (text indica el texto que se le aplicara la funci�n resumen)
	//hay que pasarle el texto, no el atajo
	public byte[] getHashCodeSHA(String text) throws IOException, NoSuchAlgorithmException{
		/* Crear funcion resumen */
		MessageDigest md = MessageDigest.getInstance("SHA"); // Usa SHA-1
		/* Leer fichero de 1k en 1k y pasar fragmentos leidos a la funcion resumen */
		byte[] buffer = new byte[1000];
		FileInputStream in = new FileInputStream(text);
		int leidos = in.read(buffer, 0, 1000);
		while (leidos != -1) {
			md.update(buffer, 0 , leidos); // Pasa texto claro a la funcion resumen
			leidos = in.read(buffer, 0, 1000);
		}
		in.close();
			
		byte[] resumen = md.digest(); // Completar el resumen
		return resumen;
			
	}
	
	//funcion para generar clave DES y almacenarla en base de datos
	// guarda el string de la secret key en base de datos
	public void setKeyDES(String id) throws NoSuchAlgorithmException{
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		String stringclave = Base64.getEncoder().encodeToString(clave.getEncoded()); //convierte la key a string
		DataBaseManager dbm=new DataBaseManager(); // para utulizar metodos de esta clase
		dbm.saveKeyDES(id,stringclave);
		
	}
	
	//recuperar clave "string" de la base de datos y devolverla como SecretKey
	public SecretKey getKeyDES(String id){
		
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
	public byte[] cifrarDES(String id, String text) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// Algoritmo DES
		// Modo : ECB (Electronic Code Book)
		// Relleno : PKCS5Padding
		SecretKey key = getKeyDES(id);
		//inicializo en modo cifrado
		cifrador.init(Cipher.ENCRYPT_MODE, key);
		//paso texto a byte y cifro
		byte[] textocifrado = cifrador.doFinal(text.getBytes());
		return textocifrado;
	}
	// el texto cifrado es la cadena resumen del texto original
	public String descifrarDES(String id, byte[] textcifrado) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		Cipher cifrador = Cipher.getInstance("DES/ECB/PKCS5Padding");
		// Algoritmo DES
		// Modo : ECB (Electronic Code Book)
		// Relleno : PKCS5Padding
		SecretKey key = getKeyDES(id);
		//inicializo en modo DEScifrado (QUE CHISTOSO SOY!!)
		cifrador.init(Cipher.DECRYPT_MODE, key);
		//paso cadena byte[] y descifro
		String textodesencriptado = new String(cifrador.doFinal(textcifrado));
		return textodesencriptado;
	}
	
	//cifrado RSA
	public byte[] encrypt(String idVote,String textToEncypt){
		
		byte[] res = null;
		try {
			Cipher rsa;
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec keySpec = new X509EncodedKeySpec(DatatypeConverter.parseBase64Binary(getPublicKeyRSA(idVote)));
			
			PublicKey pubKeyFromBytes = keyFactory.generatePublic(keySpec);
			
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.ENCRYPT_MODE, pubKeyFromBytes);
	    
		
			res = rsa.doFinal(textToEncypt.getBytes());
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			e.printStackTrace();
		} 
		
		return res;
	}
	
	//descifrado RSA
	public String decrypt(String idVote,byte[] cipherText) throws BadPaddingException{
		
		String res = null;
		try {
			Cipher rsa;
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			KeySpec keySpec = new PKCS8EncodedKeySpec(DatatypeConverter.parseBase64Binary(getPrivateKeyRSA(idVote)));
			
			PrivateKey privKeyFromBytes = keyFactory.generatePrivate(keySpec);
			
			rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, privKeyFromBytes);
			
	    
		
			byte[] bytesDesencriptados = rsa.doFinal(cipherText);
		    res = new String(bytesDesencriptados);
		} catch (IllegalBlockSizeException  | InvalidKeyException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			
			e.printStackTrace();
		}

		
		return res;
	}
	
	//metodos auxiliares (RSA):
	public boolean postKeyRSA(String id) {
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

	
	public String getPublicKeyRSA(String id) {
		RemoteDataBaseManager rdbm=new RemoteDataBaseManager();
		
		return rdbm.getPublicKey(id);
	}

	
	public String getPrivateKeyRSA(String id) {

		RemoteDataBaseManager rdbm=new RemoteDataBaseManager();
		
		
		return rdbm.getPrivateKey(id);
	}

	
	public boolean checkVoteRSA(byte[] votoCifrado, String id) {
		
		boolean res = true;
		try {
			decrypt(id, votoCifrado);
		} catch (BadPaddingException e) {
			res = false;
		}
		return res;

	}
}
