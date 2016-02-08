package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public interface Authority {

	// Recibe la id de la votación, crea las claves y las guarda en BD mediante
	// el método RSA.
	public boolean postKeyRSA(String id);

	// Recibe la id de la votación y devuelve su clave pública para poder cifrar
	// mediante el método RSA.
	public String getPublicKeyRSA(String id);

	// Recibe la id de la votación y devuelve su clave privada para poder
	// descifrar mediante el método RSA.
	public String getPrivateKeyRSA(String id);

	// Recibe un voto cifrado y un id de la votación, y comprueba si ese voto ha
	// sido alterado mediante el método RSA.
	public boolean checkVoteRSA(byte[] votoCifrado, String id);

	// Encripta el texto con la clave pública de la votación cuya id se pasa
	// como parámetro, mediante el método RSA.
	// Ademas podemos elegir que funcion resumen queremos usar (1 para MD5, 2
	// para SHA-1).
	public byte[] encryptRSA(String idVote, String textToEncypt, int option)
			throws NoSuchAlgorithmException, IOException;

	// Desencripta el texto con la clave privada de la votación cuya id se pasa
	// como parámetro, mediante el método RSA.
	public String decryptRSA(String idVote, byte[] cipherText) throws BadPaddingException;

	// Recibe la id de la votación, crea las claves y las guarda en BD mediante
	// el método DES.
	public void postKeyDES(String id) throws NoSuchAlgorithmException;

	// Recibe la id de la votación y devuelve su clave para poder cifrar y
	// descifrar mediante el método DES.
	public SecretKey getKeyDES(String id);

	// Encripta el texto con la clave de la votación cuya id se pasa como
	// parámetro, mediante el método DES.
	// Ademas podemos elegir que funcion resumen queremos usar (1 para MD5, 2
	// para SHA-1).
	public byte[] encryptDES(String id, String text, int option) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;

	// Desencripta el texto con la clave de la votación cuya id se pasa como
	// parámetro, mediante el método DES.
	public String decryptDES(String id, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;

}