package com.cheong.microservices.oauthresources.service;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

import com.cheong.microservices.oauthresources.dto.TokenDto;
import com.cheong.microservices.oauthresources.model.User;
import com.cheong.microservices.oauthresources.repository.UserRepository;

@Service
@Transactional
public class UserManager implements UserDetailsManager{
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		return userRepository.findByUsername(username).orElseThrow();
	}

	@Override
	public void createUser(UserDetails user) {
		
		((User)user).setPassword(passwordEncoder.encode(user.getPassword()));
		
		userRepository.save(((User)user));
	}

	@Override
	public void updateUser(UserDetails user) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void deleteUser(String username) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changePassword(String oldPassword, String newPassword) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public boolean userExists(String username) {
		return userRepository.existsByUsername(username);
	}
	

}
