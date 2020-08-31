package telran.ashkelon2020.forum.service;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import telran.ashkelon2020.forum.dao.ForumRepositoryMongoDB;
import telran.ashkelon2020.forum.dto.CommentDto;
import telran.ashkelon2020.forum.dto.CommentResponceDto;
import telran.ashkelon2020.forum.dto.DatePeriodDto;
import telran.ashkelon2020.forum.dto.PostDto;
import telran.ashkelon2020.forum.dto.PostResponseDto;
import telran.ashkelon2020.forum.exceptions.PostNotFoundException;
import telran.ashkelon2020.forum.model.Comment;
import telran.ashkelon2020.forum.model.Post;

@Component
public class ForumServiceImpl implements ForumService {
	
	@Autowired
	ForumRepositoryMongoDB forumRepository;
	
	@Autowired
	ModelMapper modelMapper;

	@Override
	public PostResponseDto addPost(String author, PostDto postDto) {		

		Post post = new Post(postDto.getTitle(), postDto.getContent(), author, postDto.getTags());
		Post postSaved = forumRepository.save(post);
		
		return modelMapper.map(postSaved, PostResponseDto.class);
	}

	@Override
	public PostResponseDto findPostById(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));

		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public PostResponseDto deletePost(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));

		forumRepository.delete(post);
		
		return modelMapper.map(post, PostResponseDto.class);
	}

	@Override
	public PostResponseDto updatePost(String id, PostDto postDto) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));

		String title = postDto.getTitle();
		if(title != null && !title.isEmpty()) {
			post.setTitle(title);
		}
		String content = postDto.getContent();
		if(content != null && !content.isEmpty()) {
			post.setContent(content);
		}
		
		Set<String> tags = postDto.getTags();
		if(tags != null) {
			tags.forEach(t -> post.addTag(t));
		}
		
		Post postSaved = forumRepository.save(post);
				
		return modelMapper.map(postSaved, PostResponseDto.class);
	}

	@Override
	public boolean addLikeToPost(String id) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		
		post.addLike();
		forumRepository.save(post);
		
		return true;
	}

	@Override
	public PostResponseDto addCommentToPost(String id, String author, CommentDto commentDto) {
		Post post = forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id));
		
		post.addComment(new Comment(author, commentDto.getMessage()));
		Post postSaved = forumRepository.save(post);
		
		return modelMapper.map(postSaved, PostResponseDto.class);
	}

	@Override
	public List<PostResponseDto> findPostsByAuthor(String author) {
		return forumRepository.findByAuthor(author)
				.map(p -> modelMapper.map(p, PostResponseDto.class))
				.collect(Collectors.toList());
	}

	@Override
	public Iterable<PostResponseDto> findPostsByTags(List<String> tags) {
		return forumRepository.findByTagsIn(tags)
				.map(p -> modelMapper.map(p, PostResponseDto.class))
				.collect(Collectors.toList());
				
	}

	@Override
	public Iterable<PostResponseDto> findPostsByDates(DatePeriodDto datePeriodDto) {
		return forumRepository.findByDateCreatedBetween(datePeriodDto.getDateFrom(), datePeriodDto.getDateTo())		
				.map(p -> modelMapper.map(p, PostResponseDto.class))
				.collect(Collectors.toList());
	}
	
	@Override
	public Iterable<CommentResponceDto> findAllPostComments(String id) {
		return forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id))
				.getComments().stream()
				.map(c -> modelMapper.map(c, CommentResponceDto.class))
				.collect(Collectors.toList());

				
	}

	@Override
	public Iterable<CommentResponceDto> findAllPostCommentsByAuthor(String id, String user) {
		
		return forumRepository.findById(id).orElseThrow(() -> new PostNotFoundException(id))
				.getComments().stream()
				.filter(c -> user.equalsIgnoreCase(c.getUser()))
				.map(c -> modelMapper.map(c, CommentResponceDto.class))
				.collect(Collectors.toList());
	}

}