package main;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AuxClass {
	
	//funcion resumen con md5 (text indica el texto que se le aplicara la función resumen)
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
	
	//funcion resumen con SHA-1 (text indica el texto que se le aplicara la función resumen)
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
	
}
