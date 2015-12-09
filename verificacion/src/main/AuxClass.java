package main;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

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
	
	//funcion para generar clave DES y almacenarla en base de datos
	//devuelve secret key, pero guarda string en base de datos
	public SecretKey getKeyDES(String id) throws NoSuchAlgorithmException{
		KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
		generadorDES.init(56); // clave de 56 bits
		SecretKey clave = generadorDES.generateKey();
		String stringclave = Base64.getEncoder().encodeToString(clave.getEncoded()); //convierte la key a string
		DataBaseManager dbm=new DataBaseManager(); // para utulizar metodos de esta clase
		dbm.saveKeyDES(id,stringclave);
		
		return clave;
	}
	
	
}
