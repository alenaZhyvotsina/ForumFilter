package telran.ashkelon2020.accounting.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(of = "login")
@ToString
@Document(collection = "users")
public class User {
		
	@Id
	String login;
	String password;
	String firstName;
	String lastName;
	LocalDateTime expDate;  // now() + 30 days
	Set<String> roles; // ADMIN, MODERATOR, USER (default)
	
	public User(String login, String password, String firstName, String lastName, Set<String> roles) {
		this.login = login;
		this.password = password;
		this.firstName = firstName;
		this.lastName = lastName;
		this.roles = new HashSet<>();
		
		if(roles != null && !roles.isEmpty()) {
			roles.forEach(r -> addRole(r));			
		}		
	}
	
	public User(String login, String password, String firstName, String lastName) {
		this(login, password, firstName, lastName, new HashSet<String>());
	}
	
	public boolean addRole(String role) {
		if(role == null || role.isEmpty()) {
			return false;
		}
		return this.roles.add(role.toUpperCase());
	}
	
	public boolean deleteRole(String role) {
		if(role == null || role.isEmpty()) {
			return false;
		}
		return this.roles.remove(role.toUpperCase());
	}
	
	

}
