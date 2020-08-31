package telran.ashkelon2020.forum.dto;

import java.time.LocalDateTime;
import java.util.Set;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor
public class PostResponseDto {
	
	String id;
	@Setter
	String title;
	@Setter
	String content;
	String author;
	LocalDateTime dateCreated;
	@Setter
	Set<String> tags;
	//String[] tags;
	Integer likes;
	@Setter
	Set<CommentResponceDto> comments;
	//Comment[] comments;

}
