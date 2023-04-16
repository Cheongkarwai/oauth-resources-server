package com.cheong.microservices.oauthresources.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cheong.microservices.oauthresources.model.User;

public interface UserRepository extends JpaRepository<User, String>{

	Optional<User> findByUsername(String username);
	
	boolean existsByUsername(String username);
}
