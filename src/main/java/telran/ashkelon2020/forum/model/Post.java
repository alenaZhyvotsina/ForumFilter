package telran.ashkelon2020.forum.model;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.Singular;

@Getter
@NoArgsConstructor
@EqualsAndHashCode(of = "id")
public class Post {
	
	String id;
	@Setter
	String title;
	@Setter
	String content;
	String author;
	LocalDateTime dateCreated;
	@Singular
	Set<String> tags;
	int likes;
	@Singular
	Set<Comment> comments;
	
	public Post(String title, String content, String author, Set<String> tags) {
		this.title = title;
		this.content = content;
		this.author = author;
		this.tags = tags;
		
		this.dateCreated = LocalDateTime.now();
		comments = new HashSet<Comment>();
	}
		
	public Post(String title, String content, String author) {
		this(title, content, author, new HashSet<String>());
	}
	
	public void addComment(Comment comment) {
		this.comments.add(comment);
	}
	
	public boolean deleteComment(Comment comment) {
		return this.comments.remove(comment);
	}
	
	public void addTag(String tag) {
		this.tags.add(tag);
	}
	
	public boolean deleteTag(String tag) {
		return this.tags.remove(tag);
	}
	
	public void addLike() {
		likes++;
	}
	
	
}
