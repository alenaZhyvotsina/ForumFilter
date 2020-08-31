package telran.ashkelon2020.accounting.service;

import telran.ashkelon2020.accounting.dto.UserDto;
import telran.ashkelon2020.accounting.dto.UserNewDto;
import telran.ashkelon2020.accounting.dto.UserUpdDto;

public interface UserService {
	
	UserDto addUser(UserNewDto userDto);
	
	UserDto findUser(String login);
	
	UserDto deleteUser(String login);
	
	UserDto updateUser(String login, UserUpdDto userUpdDto);
	
	UserDto changeRoleList(String login, String role, boolean toAdd);
		
	UserDto changePassword(String login, String newPassword);

}
