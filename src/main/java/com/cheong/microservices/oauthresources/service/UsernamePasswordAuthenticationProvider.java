package com.cheong.microservices.oauthresources.service;

import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import com.cheong.microservices.oauthresources.model.User;

@Component
public class UsernamePasswordAuthenticationProvider implements AuthenticationProvider{
	
	@Autowired
	private UserDetailsManager userDetailsManager;
	
	@Autowired
	private PasswordEncoder passwordEncoder;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		if(userDetailsManager.userExists(authentication.getName())) {
			UserDetails userDetails = userDetailsManager.loadUserByUsername(authentication.getName());
			
			if(userDetails.getUsername().equals(authentication.getName()) && passwordEncoder.matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
				
				return new UsernamePasswordAuthenticationToken(authentication.getPrincipal(), userDetails.getPassword(),Collections.emptyList());
			}
		}
		
		throw new BadCredentialsException("User not found");
	}

	@Override
	public boolean supports(Class<?> authentication) {
		// TODO Auto-generated method stub
		return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}

}
