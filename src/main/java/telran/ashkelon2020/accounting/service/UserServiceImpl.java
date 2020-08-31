package telran.ashkelon2020.accounting.service;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.mindrot.jbcrypt.BCrypt;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jmx.export.annotation.ManagedAttribute;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.stereotype.Service;

import telran.ashkelon2020.accounting.dao.UserRepositoryMongoDB;
import telran.ashkelon2020.accounting.dto.UserDto;
import telran.ashkelon2020.accounting.dto.UserNewDto;
import telran.ashkelon2020.accounting.dto.UserUpdDto;
import telran.ashkelon2020.accounting.exception.UserExistsEsception;
import telran.ashkelon2020.accounting.exception.UserNotFoundException;
import telran.ashkelon2020.accounting.model.User;

@Service
@ManagedResource  // управляемый ресурс (извне приложения - JMXת,MBean technologies)
public class UserServiceImpl implements UserService {
	
	@Autowired
	UserRepositoryMongoDB userRepository;
	
	@Autowired
	ModelMapper modelMapper;

	@Value("${expdate.value}")
	private long period;

	@Value("${default.role}")
	private String defaultUser;
	
	@ManagedAttribute  // можно посмотреть значение in Runtime - in application.properties - spring.jmx.enabled=true
	public long getPeriod() {
		return period;
	}

	@ManagedAttribute
	public void setPeriod(long period) {
		this.period = period;
	}
	
	public String getDefaultUser() {
		return defaultUser;
	}

	public void setDefaultUser(String defaultUser) {
		this.defaultUser = defaultUser;
	}

	@Override
	public UserDto addUser(UserNewDto userNewDto) {
		if(userRepository.existsById(userNewDto.getLogin())) {
			throw new UserExistsEsception(userNewDto.getLogin());
		}
		
		String hashPassword = BCrypt.hashpw(userNewDto.getPassword(), BCrypt.gensalt());
		
		Set<String> roles = userNewDto.getRoles();		
		if(roles == null || roles.isEmpty()) {
			roles = new HashSet<>();
		}
		
		User user = 
				new User(userNewDto.getLogin(), hashPassword, 
						 userNewDto.getFirstName(), userNewDto.getLastName(), roles);
		
		user.setExpDate(LocalDateTime.now().plusDays(period));
		user.addRole(defaultUser);
		
		User userSaved = userRepository.save(user);
		return modelMapper.map(userSaved, UserDto.class);
	}

	@Override
	public UserDto findUser(String login) {	
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));		
			
		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto deleteUser(String login) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		userRepository.deleteById(login);
		
		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto updateUser(String login, UserUpdDto userUpdDto) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		
		String name = userUpdDto.getFirstName();
		if(name != null && !name.isEmpty()) {
			user.setFirstName(name);
		}
		String surname = userUpdDto.getLastName();
		if(surname != null && !surname.isEmpty()) {
			user.setLastName(surname);
		}
		
		User userSaved = userRepository.save(user);
		
		return modelMapper.map(userSaved, UserDto.class);
	}

	@Override
	public UserDto changeRoleList(String login, String role, boolean toAdd) {
		
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));
		boolean res;
		
		if(toAdd) {
			res = user.addRole(role);
		} else {
			res = user.deleteRole(role);
		}
		
		if(res) {
			user = userRepository.save(user);
		}
				
		return modelMapper.map(user, UserDto.class);
	}

	@Override
	public UserDto changePassword(String login, String newPassword) {
		User user = userRepository.findById(login).orElseThrow(() -> new UserNotFoundException(login));		
		String hashPassword = BCrypt.hashpw(newPassword, BCrypt.gensalt());
		
		user.setPassword(hashPassword);
		user.setExpDate(LocalDateTime.now().plusDays(period));
		
		User userSaved = userRepository.save(user);
		
		return modelMapper.map(userSaved, UserDto.class);
	}

}
