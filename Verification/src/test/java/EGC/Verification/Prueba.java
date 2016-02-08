package EGC.Verification;

public class Prueba {
	
	public static void main(String[] args) {
		
		Authority authority = new AuthorityImpl();
		
		if(authority.postKeyRSA(String.valueOf(1000))){
			System.out.println("Guardado");
		}
		else{
			System.out.println("Error al intentar guardar");
		}
		if(authority.postKeyRSA(String.valueOf(999))){
			System.out.println("Guardado");
		}
		else{
			System.out.println("Error al intentar guardar");
		}
		
		String first = authority.getPublicKeyRSA(String.valueOf(1000));
		String second = authority.getPrivateKeyRSA(String.valueOf(999));
		System.out.println(first);
		System.out.println(second);
		System.out.println(first.equals(second));
		
		
		/*DataBaseManager dbm=new DataBaseManager();
		//dbm.getVoteFromDataBase("a1");
		System.out.println(dbm.getPrivateKey("a1"));*/
	}
}