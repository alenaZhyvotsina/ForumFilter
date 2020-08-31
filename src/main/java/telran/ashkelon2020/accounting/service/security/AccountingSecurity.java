package telran.ashkelon2020.accounting.service.security;

public interface AccountingSecurity {
	
	String getLogin(String token);
	
	boolean checkExpDate(String login);
	
	boolean checkAdmin(String login, String role);
	
	boolean isBanned(String login);
	
	String addUser(String sessionId, String login);
	
	String getUser(String sessionId);
	
	String removeUser(String sessionId);

}
