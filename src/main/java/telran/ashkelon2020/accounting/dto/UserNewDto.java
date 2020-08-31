package telran.ashkelon2020.accounting.dto;

import java.util.HashSet;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter 
@NoArgsConstructor
@AllArgsConstructor
public class UserNewDto {
	
	String login;
	String password;
	String firstName;
	String lastName;
	Set<String> roles = new HashSet<String>(); // ADMIN, MODERATOR, USER (default)

}
