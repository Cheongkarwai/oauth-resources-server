package com.cheong.microservices.oauthresources.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/hi")
public class HiController {

	@GetMapping
	public String hi() {
		
		System.out.println(SecurityContextHolder.getContext().getAuthentication().getCredentials());
		return "hi";
	}
}
