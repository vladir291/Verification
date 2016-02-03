package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AuthorityImpl implements Authority {

	

	public boolean checkVoteRSA(byte[] votoCifrado, String id) {
		boolean result;

		result = AuxClass.checkVoteRSA(votoCifrado, id);

		return result;
	}

	public byte[] encryptRSA(String idVote, String textToEncypt)
			throws NoSuchAlgorithmException, IOException {
		byte[] result = null;

		result = AuxClass.encryptRSA(idVote, textToEncypt);
			
		return result;
	}

	public String decryptRSA(String idVote, byte[] cipherText) throws BadPaddingException {
		String result;

		result = AuxClass.decryptRSA(idVote, cipherText);

		return result;
	}



	public byte[] encryptDES(String id, String text) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] result = null;
	
		result = AuxClass.encryptDES(id, text);
		
		return result;
	}

	public String decryptDES(String id, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String result;

		result = AuxClass.decryptDES(id, textCifrado);

		return result;
	}

	@Override
	public byte[] getMD5(String text) {
		byte[] result = null;
		try {
			result = AuxClass.getHashCodeMD5(text);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public byte[] getSHA1(String text) {
		byte[] result = null;
		try {
			result = AuxClass.getHashCodeSHA(text);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public boolean checkVoteDes(String text, byte[] resumen) {
		boolean res = false;
		try {
			byte[] md5 = AuxClass.getHashCodeMD5(text);
			byte[] sha = AuxClass.getHashCodeSHA(text);
			
			if(resumen.equals(md5) || resumen.equals(sha)){
				res  = true;
			}
		} catch (NoSuchAlgorithmException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return res;
	}


}
