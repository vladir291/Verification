package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public interface Authority {
	
	
	//Recibe un voto cifrado y un id de la votación, y comprueba si ese voto ha sido alterado mediante el método RSA.
	public boolean checkVoteRSA(byte[] votoCifrado, String id);
	
	//Encripta el texto con la clave pública de la votación cuya id se pasa como parámetro,  mediante el método RSA.
	//Ademas podemos elegir que funcion resumen queremos usar (1 para MD5, 2 para SHA-1).
	public byte[] encryptRSA(String idVote, String textToEncypt) throws NoSuchAlgorithmException, IOException;
	
	//Desencripta el texto con la clave privada de la votación cuya id se pasa como parámetro, mediante el método RSA.
	public String decryptRSA(String idVote,byte[] cipherText) throws BadPaddingException;
	
	//Encripta el texto con la clave de la votación cuya id se pasa como parámetro,  mediante el método DES.
	//Ademas podemos elegir que funcion resumen queremos usar (1 para MD5, 2 para SHA-1).
	public byte[] encryptDES(String id, String text) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;
	
	//Desencripta el texto con la clave de la votación cuya id se pasa como parámetro, mediante el método DES.
	public String decryptDES(String id, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;
	
	//Recibe un texto y devuelve su resumen único tipo byte, que identifica el texto y su integridad mediante MD5.
	public byte[] getMD5(String text);
	
	//Recibe un texto y devuelve su resumen único tipo byte, que identifica el texto y su integridad mediante SHA1.
	public byte[] getSHA1(String text);
	
	//Recibe un texto y un resumen y comprueba que el resumen sea del texto, identificando si hubo cambios en el texto.
	//comprueba la integridad del voto, identificando el mas mínimo cambio sobre este.
	public boolean checkVoteDes(String text, byte[] resumen);

}