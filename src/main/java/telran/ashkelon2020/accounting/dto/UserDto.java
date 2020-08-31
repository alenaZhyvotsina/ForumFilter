package telran.ashkelon2020.accounting.dto;

import java.time.LocalDateTime;
import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Getter 
@NoArgsConstructor
@AllArgsConstructor
@NonNull
public class UserDto {
	
	String login;
	//String password;
	String firstName;
	String lastName;
	LocalDateTime expDate;  // now() + 30 days
	Set<String> roles; // ADMIN, MODERATOR, USER (default)

}
