package com.careerhub.joblisting.payload.response;

import java.util.List;

public class JwtResponse {
	private String token;
	private Long id;
	private String username;
	private String password;
	private List<String> roles;
	
	public JwtResponse(String token, Long id, String username, String password, List<String> roles) {
		super();
		this.token = token;
		this.id = id;
		this.username = username;
		this.password = password;
		this.roles = roles;
	}
	
	
}
