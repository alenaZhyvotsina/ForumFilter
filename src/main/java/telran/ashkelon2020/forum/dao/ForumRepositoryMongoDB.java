package telran.ashkelon2020.forum.dao;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Stream;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import telran.ashkelon2020.forum.model.Comment;
import telran.ashkelon2020.forum.model.Post;

public interface ForumRepositoryMongoDB extends MongoRepository<Post, String> {
	
	Stream<Post> findByAuthor(String author);
	
	Stream<Post> findByTagsIn(List<String> tags);  // one of
	Stream<Post> findByTagsContaining(List<String> tags);  // all
	
	//Stream<Post> findByDateCreatedBetween(LocalDateTime dateFrom, LocalDateTime dateTo);  //не обязательно DateTime
	Stream<Post> findByDateCreatedBetween(LocalDate dateFrom, LocalDate dateTo);
	
	@Query("{_id: ?0}}, {comments: 1}")
	Stream<Comment> findAllPostComments(String id);
	//{comments: 1, _id: 0, title: 0, content: 0, author: 0, dateCreated: 0, tags: 0, likes: 0, _class: 0}
	
	@Query("{$and: [{_id: ?0}, {'comments.user': ?1}]}, {comments: 1}")
	Stream<Comment> findAllPostCommentsByAuthor(String id, String author);

}
