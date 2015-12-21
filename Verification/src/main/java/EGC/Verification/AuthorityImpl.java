package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AuthorityImpl implements Authority {

	public boolean postKeyRSA(String id) {
		boolean result;

		result = AuxClass.postKeyRSA(id);

		return result;
	}

	public String getPublicKeyRSA(String id) {
		String result;

		result = AuxClass.getPublicKeyRSA(id);

		return result;
	}

	public String getPrivateKeyRSA(String id) {
		String result;

		result = AuxClass.getPrivateKeyRSA(id);

		return result;
	}

	public boolean checkVoteRSA(byte[] votoCifrado, String id) {
		boolean result;

		result = AuxClass.checkVoteRSA(votoCifrado, id);

		return result;
	}

	public byte[] encryptRSA(String idVote, String textToEncypt, int option)
			throws NoSuchAlgorithmException, IOException {
		byte[] result = null;
		byte[] resumen = null;

		switch (option) {
		case 1:
			resumen = AuxClass.getHashCodeMD5(textToEncypt);
			result = AuxClass.encryptRSA(idVote, resumen);
		case 2:
			resumen = AuxClass.getHashCodeSHA(textToEncypt);
			result = AuxClass.encryptRSA(idVote, resumen);
		}

		return result;
	}

	public String decryptRSA(String idVote, byte[] cipherText) throws BadPaddingException {
		String result;

		result = AuxClass.decryptRSA(idVote, cipherText);

		return result;
	}

	public void postKeyDES(String id) throws NoSuchAlgorithmException {

		AuxClass.postKeyDES(id);

	}

	public SecretKey getKeyDES(String id) {
		SecretKey result;

		result = AuxClass.getKeyDES(id);

		return result;

	}

	public byte[] encryptDES(String id, String text, int option) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] result = null;
		byte[] resumen = null;

		switch (option) {
		case 1:
			resumen = AuxClass.getHashCodeMD5(text);
			result = AuxClass.encryptDES(id, resumen);
		case 2:
			resumen = AuxClass.getHashCodeSHA(text);
			result = AuxClass.encryptDES(id, resumen);
		}

		return result;
	}

	public String decryptDES(String id, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String result;

		result = AuxClass.decryptDES(id, textCifrado);

		return result;
	}

}
