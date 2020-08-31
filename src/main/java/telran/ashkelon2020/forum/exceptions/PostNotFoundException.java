package telran.ashkelon2020.forum.exceptions;

public class PostNotFoundException extends RuntimeException{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public PostNotFoundException(String id) {
		super("Post with id = " + id + " not found"); 
	}

}
