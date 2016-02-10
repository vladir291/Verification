package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public interface Authority {
	
	
	//Recibe un voto cifrado y keypair(publica y privada), y comprueba si ese voto ha sido alterado mediante el método RSA.
	public boolean checkVoteRSA(byte[] votoCifrado, KeyPair key);
	
	//Encripta el texto con la clave pública de la votación del key pair,  mediante el método RSA.
	public byte[] encryptRSA(KeyPair key, String textToEncypt) throws NoSuchAlgorithmException, IOException;
	
	//Desencripta el texto con la clave privada de la votación ontenida del keypair, mediante el método RSA.
	public String decryptRSA(KeyPair key,byte[] cipherText) throws BadPaddingException;
	
	//Encripta el texto con la clave dsecreta,  mediante el método DES.
	public byte[] encryptDES(SecretKey key, String text) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;
	
	//Desencripta el texto con la clave secreta que se pasa como parámetro, mediante el método DES.
	public String decryptDES(SecretKey key, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException;
	
	//Recibe un texto y devuelve su resumen único tipo byte, que identifica el texto y su integridad mediante MD5.
	public byte[] getMD5(String text);
	
	//Recibe un texto y devuelve su resumen único tipo byte, que identifica el texto y su integridad mediante SHA1.
	public byte[] getSHA1(String text);
	
	//Recibe un texto y un resumen y comprueba que el resumen sea del texto, identificando si hubo cambios en el texto.
	//comprueba la integridad del voto, identificando el mas mínimo cambio sobre este.
	public boolean checkVoteDes(String text, byte[] resumen);
	
	//devuelve una clave secreta utilizable en DES.
	public SecretKey getKeyDes();

	//devuelve un par clave publica y privada utilizavle en RSA.
	public KeyPair getKeysRsa();
}