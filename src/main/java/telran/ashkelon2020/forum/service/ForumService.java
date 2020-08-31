package telran.ashkelon2020.forum.service;

import java.util.List;

import telran.ashkelon2020.forum.dto.CommentResponceDto;
import telran.ashkelon2020.forum.dto.CommentDto;
import telran.ashkelon2020.forum.dto.DatePeriodDto;
import telran.ashkelon2020.forum.dto.PostDto;
import telran.ashkelon2020.forum.dto.PostResponseDto;

public interface ForumService {
	
	PostResponseDto addPost(String author, PostDto postDto);
	
	PostResponseDto findPostById(String id);
	
	PostResponseDto deletePost(String id);
	
	PostResponseDto updatePost(String id, PostDto postDto);
	
	boolean addLikeToPost(String id);
	
	PostResponseDto addCommentToPost(String id, String author, CommentDto commentDto);
	
	//PostResponseDto[] findPostsByAuthor(String author);
	List<PostResponseDto> findPostsByAuthor(String author);
	
	Iterable<PostResponseDto> findPostsByTags(List<String> tags);  //all
	
	Iterable<PostResponseDto> findPostsByDates(DatePeriodDto datePeriodDto);
	
	Iterable<CommentResponceDto> findAllPostComments(String id);
		
	Iterable<CommentResponceDto> findAllPostCommentsByAuthor(String id, String author);
	

}
