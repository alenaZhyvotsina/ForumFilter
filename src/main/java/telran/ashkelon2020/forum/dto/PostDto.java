package telran.ashkelon2020.forum.dto;

import java.util.Set;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Setter
public class PostDto {
	
	String title;
	String content;
	Set<String> tags;
	//String[] tags;

}
