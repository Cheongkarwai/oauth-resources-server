package com.cheong.microservices.oauthresources.controller;

import java.util.Collection;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.cheong.microservices.oauthresources.dto.LoginDto;
import com.cheong.microservices.oauthresources.dto.SignUpDto;
import com.cheong.microservices.oauthresources.dto.TokenDto;
import com.cheong.microservices.oauthresources.model.User;
import com.cheong.microservices.oauthresources.service.TokenService;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
	
	@Autowired
	@Qualifier("userManager")
	private UserDetailsManager userDetailsManager;
	
	@Autowired
	private TokenService tokenGenerator;
	
	@Autowired
	private DaoAuthenticationProvider authenticationProvider;
	
	@Autowired
	@Qualifier("jwtRefreshTokenAuthProvider")
	private JwtAuthenticationProvider refreshTokenAuthenticationProvider;
	

	@PostMapping("/register")
	public HttpEntity<?> register(@RequestBody SignUpDto signUpDto) {
		
		User user = new User(signUpDto.getUsername(),signUpDto.getPassword());
		
		userDetailsManager.createUser(user);
		
		Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(user, signUpDto.getPassword(), Collections.emptyList());
		
		return ResponseEntity.ok(tokenGenerator.createToken(authentication));
	}
	
	@PostMapping("/login")
	public HttpEntity<?> login(@RequestBody LoginDto loginDto){
		
		
		Authentication authentication = authenticationProvider
				.authenticate(UsernamePasswordAuthenticationToken.unauthenticated(loginDto.getUsername(), loginDto.getPassword()));
		
		System.out.println(authentication.getCredentials());
		
		return ResponseEntity.ok(tokenGenerator.createToken(authentication));
	}
	
	@PostMapping("/token")
	public HttpEntity<?> generateToken(@RequestBody TokenDto tokenDto){
		
		System.out.println(refreshTokenAuthenticationProvider.authenticate(new BearerTokenAuthenticationToken(tokenDto.getRefreshToken())));
		
		System.out.println(tokenDto.getRefreshToken());
		
		Authentication authentication = refreshTokenAuthenticationProvider.authenticate(new BearerTokenAuthenticationToken(tokenDto.getRefreshToken()));
		
		return ResponseEntity.ok(tokenGenerator.createToken(authentication));
	}
}
