package com.careerhub.joblisting.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.careerhub.joblisting.models.ERole;
import com.careerhub.joblisting.models.Role;
import com.careerhub.joblisting.models.User;
import com.careerhub.joblisting.payload.request.LoginRequest;
import com.careerhub.joblisting.payload.request.SignupRequest;
import com.careerhub.joblisting.payload.response.JwtResponse;
import com.careerhub.joblisting.payload.response.MessageResponse;
import com.careerhub.joblisting.repository.RoleRepository;
import com.careerhub.joblisting.repository.UserRepository;
import com.careerhub.joblisting.security.jwt.JwtUtils;
import com.careerhub.joblisting.security.service.UserDetailsImpl;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;

	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);

		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());

		return ResponseEntity.ok(
				new JwtResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestParam String username, @RequestParam String email,
			@RequestParam String password, @RequestParam(value = "role", required = false) String role) {

		// Set default role to "USER" if not provided
	    Set<String> strRoles = new HashSet<>();
	    if (role != null && !role.isEmpty()) {
	        strRoles.add(role);
	    } else {
	        strRoles.add("USER");
	    }

	    // Create SignupRequest object
	    SignupRequest signUpRequest = SignupRequest.builder()
	            .username(username)
	            .email(email)
	            .password(password)
	            .role(strRoles)
	            .build();

	    // Check if username or email already exists
	    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
	        return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
	    }

	    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
	        return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
	    }

	    // Retrieve roles from database and assign to the user
	    Set<Role> roles = strRoles.stream()
	            .map(roleName -> {
	                ERole eRole = ERole.valueOf(roleName);
	                return roleRepository.findByName(eRole)
	                        .orElseThrow(() -> new RuntimeException("Error: Role '" + eRole + "' is not found."));
	            })
	            .collect(Collectors.toSet());

	    // Create user object
	    User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
	            encoder.encode(signUpRequest.getPassword()));
	    user.setRoles(roles);

	    // Save user to the database
	    userRepository.save(user);

	    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

}
