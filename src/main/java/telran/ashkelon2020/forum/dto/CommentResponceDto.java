package telran.ashkelon2020.forum.dto;

import java.time.LocalDateTime;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Setter
public class CommentResponceDto {
	String user;
	String message;
	LocalDateTime dateCreated;
	Integer likes;
	
	
}
