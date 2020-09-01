package telran.ashkelon2020.accounting.service.security;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.dto.UserLoginDto;
import telran.ashkelon2020.accounting.exception.ForbiddenException;
import telran.ashkelon2020.accounting.exception.NotAdminException;
import telran.ashkelon2020.accounting.exception.TokenValidateException;
import telran.ashkelon2020.accounting.exception.UnauthorizedException;
import telran.ashkelon2020.accounting.exception.UserNotFoundException;
import telran.ashkelon2020.accounting.model.User;

@Service
public class AccountSecurityImpl implements AccountingSecurity {

	Map<String, String> users = new ConcurrentHashMap<>();
	
	@Autowired
	UserRepositoryMongoDB userRepository;
	
	@Override
	public String getLogin(String token) {
		UserLoginDto userLoginDto = tokenDecode(token);
		User user = 
				userRepository.findById(userLoginDto.getLogin())
					.orElseThrow(() -> new UserNotFoundException(userLoginDto.getLogin()));		
		
		if(!BCrypt.checkpw(userLoginDto.getPassword(), user.getPassword())) {
			throw new UnauthorizedException();
		}
		/*
		if(isBanned(user.getLogin())) {
			throw new ForbiddenException();
		}
		*/
		return user.getLogin();
	}
	
	private UserLoginDto tokenDecode(String token) {
		try {
			String[] credentials = token.split(" ");
			String credential = new String(Base64.getDecoder().decode(credentials[1]));
			credentials = credential.split(":");
			return new UserLoginDto(credentials[0], credentials[1]);
		} catch (Exception e) {
			throw new TokenValidateException();
		}
	}

	@Override
	public boolean checkExpDate(String login) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));		
		
		if(user.getExpDate().isBefore(LocalDateTime.now())) {
			throw new ForbiddenException();
		}
		return true;
	}
	
	@Override
	public boolean checkAdmin(String login, String role) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		
		if(user.getRoles().contains(role.toUpperCase())) {
			return true;
		}
		else {
			throw new NotAdminException(login, role);
		}		
	}

	@Override
	public boolean isBanned(String login) {
		User user = userRepository.findById(login)
				.orElseThrow(() -> new UserNotFoundException(login));
		
		return user.getRoles().isEmpty();
	}

	@Override
	public String addUser(String sessionId, String login) {
		return users.put(sessionId, login);
	}

	@Override
	public String getUser(String sessionId) {
		return users.get(sessionId);
	}

	@Override
	public String removeUser(String sessionId) {
		return users.remove(sessionId);
	}

}
