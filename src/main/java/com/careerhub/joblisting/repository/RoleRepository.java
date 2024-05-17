package com.careerhub.joblisting.repository;

import java.util.Optional;

import org.springframework.stereotype.Repository;

import com.careerhub.joblisting.models.ERole;
import com.careerhub.joblisting.models.Role;

@Repository
public interface RoleRepository {
	Optional<Role> findByName(ERole name);
}
