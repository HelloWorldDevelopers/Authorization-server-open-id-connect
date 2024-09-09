/*
 * package com.authorizatiion.demo;
 * 
 * 
 * import org.springframework.beans.factory.annotation.Autowired; import
 * org.springframework.security.core.userdetails.User; import
 * org.springframework.security.core.userdetails.UserDetails; import
 * org.springframework.security.core.userdetails.UserDetailsService; import
 * org.springframework.security.core.userdetails.UsernameNotFoundException;
 * import org.springframework.stereotype.Service;
 * 
 * @Service public class CustomUserDetailsService implements UserDetailsService
 * {
 * 
 * @Autowired private UserRepository userRepository;
 * 
 * @Override public UserDetails loadUserByUsername(String username) throws
 * UsernameNotFoundException { UserEntity userEntity =
 * userRepository.findByUsername(username); if (userEntity == null) { throw new
 * UsernameNotFoundException("User not found"); } return
 * User.withUsername(userEntity.getUsername())
 * .password(userEntity.getPassword())
 * .authorities(userEntity.getRoles().split(",")) // Assuming roles are stored
 * as comma-separated values .build(); } }
 */