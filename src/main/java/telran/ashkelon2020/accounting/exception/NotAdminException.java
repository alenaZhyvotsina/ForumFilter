package telran.ashkelon2020.accounting.exception;

public class NotAdminException extends RuntimeException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	public NotAdminException(String login) {
		super("User " + login + " isn't Administrator!");
	}

}
