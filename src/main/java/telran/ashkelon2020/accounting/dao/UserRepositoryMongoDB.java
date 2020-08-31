package telran.ashkelon2020.accounting.dao;

import org.springframework.data.mongodb.repository.MongoRepository;

import telran.ashkelon2020.accounting.model.User;

public interface UserRepositoryMongoDB extends MongoRepository<User, String> {

}
