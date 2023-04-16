package com.cheong.microservices.oauthresources.service;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import com.cheong.microservices.oauthresources.dto.TokenDto;
import com.cheong.microservices.oauthresources.model.User;
import com.cheong.microservices.oauthresources.repository.UserRepository;

@Service
@Transactional
public class TokenService {

	@Autowired
	private JwtEncoder accessTokenEncoder;
	
	@Autowired
	@Qualifier("jwtRefreshTokenEncoder")
	private JwtEncoder refreshTokenEncoder;
	
	@Autowired
	private UserRepository userRepository;
	
	
	public String createAccessToken(Authentication authentication) {
		User user = (User) authentication.getPrincipal();
		Instant now = Instant.now();
		
		JwtClaimsSet claimsSet = JwtClaimsSet.builder()
					.issuer("MyApp")
					.issuedAt(Instant.now())
					.claim("scope", Arrays.asList("ROLES_ADMIN","ROLES_MANAGER"))
					.expiresAt(now.plus(1,ChronoUnit.HOURS))
					.subject(user.getUsername())
					.build();
					
		return accessTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
	}
	
	public String createRefreshToken(Authentication authentication) {
		User user = (User) authentication.getPrincipal();
		Instant now = Instant.now();
		
		JwtClaimsSet claimsSet = JwtClaimsSet.builder()
					.issuer("MyApp")
					.issuedAt(now)
					.claim("scope", Arrays.asList("ROLES_ADMIN","ROLES_MANAGER"))
					.expiresAt(now.plus(1,ChronoUnit.DAYS))
					.subject(user.getUsername())
					.build();
					
		return refreshTokenEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
	}
	
	
	public TokenDto createToken(Authentication authentication) {
		
		User user = (User) authentication.getPrincipal();

		
		
		if(!(authentication.getPrincipal() instanceof User)) {
			throw new BadCredentialsException("Not User Type");
		}
		
		
		TokenDto tokenDto = TokenDto.builder()
								.userId(user.getUsername())
								.accessToken(createAccessToken(authentication))
								.build();
		
		String refreshToken;
		
		if(authentication.getCredentials() instanceof Jwt) {
			
			Jwt jwtToken = (Jwt) authentication.getCredentials();
			Instant expiresAt = jwtToken.getExpiresAt();
			Duration duration = Duration.between(Instant.now(),expiresAt);
			
			System.out.println("Hi"+jwtToken);
			
			long daysUntilExpired = duration.toDays();
			
			if(daysUntilExpired < 7) {
				refreshToken = createRefreshToken(authentication);
			}else {
				refreshToken = jwtToken.getTokenValue();
			}
		}else{
			refreshToken = createRefreshToken(authentication);
		}
		
		tokenDto.setRefreshToken(refreshToken);
		
		
		return tokenDto;
	}
	
}
