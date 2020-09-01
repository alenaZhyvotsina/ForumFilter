package telran.ashkelon2020.accounting.exception;

public class NotAdminException extends RuntimeException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public NotAdminException(String login, String role) {
		super("User " + login + " doesn/t have role " + role + "!");
	}

}
