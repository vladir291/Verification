package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AuthorityImpl implements Authority {

	

	public boolean checkVoteRSA(byte[] votoCifrado, KeyPair key) {
		boolean result;

		result = AuxClass.checkVoteRSA(votoCifrado, key);

		return result;
	}

	public byte[] encryptRSA(KeyPair key, String textToEncypt)
			throws NoSuchAlgorithmException, IOException {
		byte[] result = null;

		result = AuxClass.encryptRSA(key, textToEncypt);
			
		return result;
	}

	public String decryptRSA(KeyPair key, byte[] cipherText) throws BadPaddingException {
		String result;

		result = AuxClass.decryptRSA(key, cipherText);

		return result;
	}

	//obtener clave des
	public SecretKey getKeyDes(){
		return AuxClass.returnKeyDes();
	}
	
	//obtener claves rsa
	public KeyPair getKeysRsa(){
		return AuxClass.returnKeysRSA();
	}

	public byte[] encryptDES(SecretKey key, String text) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] result = null;
	
		result = AuxClass.encryptDES(key, text);
		
		return result;
	}

	public String decryptDES(SecretKey key, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String result;

		result = AuxClass.decryptDES(key, textCifrado);

		return result;
	}

	@Override
	public byte[] getMD5(String text) {
		byte[] result = null;
		result = AuxClass.getHashCodeMD5(text);
		return result;
	}

	@Override
	public byte[] getSHA1(String text) {
		byte[] result = null;
		result = AuxClass.getHashCodeSHA(text);
		return result;
	}

	@Override
	public boolean checkVoteDes(String text, byte[] resumen) {
		boolean res = false;
		byte[] md5 = AuxClass.getHashCodeMD5(text);
		byte[] sha = AuxClass.getHashCodeSHA(text);
		
		if(resumen.equals(md5) || resumen.equals(sha)){
			res  = true;
		}

		return res;
	}


}
