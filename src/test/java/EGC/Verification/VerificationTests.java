package EGC.Verification;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class VerificationTests {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testCheckVoteRSA() throws NoSuchAlgorithmException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] votoCifrado = clase.encryptRSA(keys, "Esto es una prueba");
		boolean comprobacion = clase.checkVoteRSA(votoCifrado, keys);
		assertTrue("Votacion amañada", comprobacion);
	}

	@Test
	public void testEncryptRSA() throws NoSuchAlgorithmException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] res = clase.encryptRSA(keys, "Esto es una prueba");
		assertNotNull(res);
	}

	@Test
	public void testDecryptRSA() throws NoSuchAlgorithmException, IOException, BadPaddingException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] res = clase.encryptRSA(keys, "Esto es una prueba");
		String fin = clase.decryptRSA(keys, res);
		assertNotNull(fin);
	}

	@Test
	public void testGetKeyDes() {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		assertNotNull(key);
	}

	@Test
	public void testGetKeysRsa() {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		assertNotNull(keys.getPublic());
	}

	@Test
	public void testEncryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		byte[] enc = clase.encryptDES(key, "Esto es una prueba");
		assertNotNull(enc);
		System.out.println("Encriptado en DES: Esto es una prueba -> " + new String(enc));
	}

	@Test
	public void testDecryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		byte[] enc = clase.encryptDES(key,"Esto es una prueba");
		String fin = clase.decryptDES(key, enc);
		assertNotNull(fin);
		System.out.println("Desencriptado en DES: " + new String(enc) + " -> " + fin);
	}

	@Test
	public void testGetMD5() {
		AuthorityImpl clase = new AuthorityImpl();
		byte[] res = clase.getMD5("Esto es una prueba");
		assertNotNull(new String(res));
	}

	@Test()
	public void testGetSHA1() {
		AuthorityImpl clase = new AuthorityImpl();
		String s1 = "esto es una prueba";
		byte[] res = clase.getSHA1(s1);
		assertNotNull(new String(res));
	}

	@Test
	public void testCheckVoteDes() {
		AuthorityImpl clase = new AuthorityImpl();
		String texto = "Esto es una prueba";
		byte[] res = clase.getMD5("Esto es una prueba");
		boolean comprobacion = clase.checkVoteDes(texto, res);
		assertFalse("Votacion amañada", comprobacion);
	}

}
