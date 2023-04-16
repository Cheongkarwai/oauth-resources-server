package com.cheong.microservices.oauthresources.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.cheong.microservices.oauthresources.service.UsernamePasswordAuthenticationProvider;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig {
	
	private  JwtToUserConverter jwtToUserConverter;
	
	private KeyUtils keyUtils;
	
	@Autowired
	@Qualifier("userManager")
	private UserDetailsManager userDetailsManager;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	public WebSecurityConfig(JwtToUserConverter jwtToUserConverter,KeyUtils keyUtils) {
		this.jwtToUserConverter = jwtToUserConverter;
		this.keyUtils = keyUtils;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
		http
			.authorizeHttpRequests(registry->{
				registry.antMatchers("/api/v1/auth/**").permitAll()
				.anyRequest().authenticated();
			}).csrf()
			.disable()
			.cors()
			.disable()
			.oauth2ResourceServer(oauth2->oauth2.jwt(jwt->jwt.jwtAuthenticationConverter(jwtToUserConverter)))
			.sessionManagement(session->session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.exceptionHandling(exception->exception
						.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
						.accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
		
		return http.build();
	}
	
	@Bean
	@Primary
	public JwtDecoder jwtAccessTokenDecoder() {
		return NimbusJwtDecoder.withPublicKey(keyUtils.getAccessTokenPublicKey()).build();
	}
	
	@Bean
	@Primary
	public JwtEncoder jwtAccessTokenEncoder() {
		JWK jwk = new RSAKey
				.Builder(keyUtils.getAccessTokenPublicKey())
				.privateKey(keyUtils.getAccessTokenPrivateKey())
				.build();
		
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
	
	@Bean
	public JwtDecoder jwtRefreshTokenDecoder() {
		return NimbusJwtDecoder.withPublicKey(keyUtils.getRefreshTokenPublicKey()).build();
	}
	
	@Bean
	public JwtEncoder jwtRefreshTokenEncoder() {
		JWK jwk = new RSAKey
				.Builder(keyUtils.getRefreshTokenPublicKey())
				.privateKey(keyUtils.getRefreshTokenPrivateKey())
				.build();
		
		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
		return new NimbusJwtEncoder(jwks);
	}
	
	@Bean
	public JwtAuthenticationProvider jwtRefreshTokenAuthProvider() {
		JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtRefreshTokenDecoder());
		provider.setJwtAuthenticationConverter(jwtToUserConverter);
		return provider;
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(new BCryptPasswordEncoder());
		provider.setUserDetailsService(userDetailsManager);
		return provider;
		
	}
	
}
