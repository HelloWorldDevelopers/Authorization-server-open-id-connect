package com.authorizatiion.demo;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class securityConfig {
    
    private final UserRepository userRepository;
    private final ClientList clientList;
    
    public securityConfig(UserRepository userRepository,ClientList clientList) {
        this.userRepository = userRepository;
        this.clientList = clientList;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain webFilterChainForOAuth(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
        http.exceptionHandling(e -> e
            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );
        return http.build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(request -> request.requestMatchers("/register","/clients/add").permitAll()
            		
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByUserId(username)
            .map(user -> new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new Sha1PasswordEncoder();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
      	ArrayList<RegisteredClient> clients = new ArrayList<RegisteredClient>();
    	for(Clients cl : clientList.getAllClients()) {
    		var registerClient = RegisteredClient.withId(UUID.randomUUID().toString())
    	            .clientId(cl.getClientName())
    	            .clientSecret(cl.getSecretId())
    	            .scope(OidcScopes.OPENID)
    	            .scope(OidcScopes.PROFILE)
    	            .redirectUri(cl.getRedirectUri())
    	            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
     	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    	            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
    	            .authorizationGrantTypes(type -> {
    	                type.add(AuthorizationGrantType.AUTHORIZATION_CODE);
    	                type.add(AuthorizationGrantType.REFRESH_TOKEN);
    	                type.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
    	            })
    	            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
    	            .build();
    		clients.add(registerClient);
    	}
//        var registerClient = RegisteredClient.withId(UUID.randomUUID().toString())
//            .clientId("public-client-react-app")
//            .clientSecret("secret")
//            .scope(OidcScopes.OPENID)
//            .scope(OidcScopes.PROFILE)
//            .redirectUri("http://localhost:3000/redirect")
//            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//            .authorizationGrantTypes(type -> {
//                type.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                type.add(AuthorizationGrantType.REFRESH_TOKEN);
//                type.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
//            })
//            .clientSettings(ClientSettings.builder().requireProofKey(true).build())
//            .build();
//        
//        var registerClient1 = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("qms")
//                .clientSecret("secre")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .redirectUri("http://localhost:3000/redirect")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
//                .authorizationGrantTypes(type -> {
//                    type.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                    type.add(AuthorizationGrantType.REFRESH_TOKEN);
//                    type.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
//                })
//                .clientSettings(ClientSettings.builder().requireProofKey(true).build())
//                .build();
        return new InMemoryRegisteredClientRepository(clients);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        var keys = keyPairGenerator.generateKeyPair();
        var publicKey = (RSAPublicKey) keys.getPublic();
        var privateKey = keys.getPrivate();
        var rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        System.out.println("Creating AuthenticationManager bean");
        return http.getSharedObject(AuthenticationManagerBuilder.class)
            .userDetailsService(userDetailsService())
            .passwordEncoder(passwordEncoder())
            .and()
            .build();
    }

    // this is will be use for adding more claims on the token creation time
    
//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
//        return context -> {
//            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                Authentication authentication = context.getPrincipal();
//                if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
//                    UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//                    Optional<EmployeeMaster> findByUsername = userRepository.findByUserId(userDetails.getUsername());
//                    List<String> roleList = userRepository.getRoleList(findByUsername.get().getId());
//                    if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
//                        context.getClaims().claims(claims -> {
//                          claims.put("userId", userDetails.getUsername());
//              	          claims.put("staffId", findByUsername.get().getId()); 
//              	          claims.put("fullName", findByUsername.get().getfName()+" "+findByUsername.get().getlName());
//              	          claims.put("emailId",findByUsername.get().getEmailId());
//              		     // claims.put("role",roleList);
//              			//  claims.put("rbac",rbacList);
//              			//  claims.put("ipAddress",ipAddress);
//                        });
//                        Instant now = Instant.now();
//                        Instant expirationTime = now.plus(Duration.ofMinutes(20)); // Set token validity to 20 minutes
//                        context.getClaims().expiresAt(expirationTime);
//                    }
//                }
//            }
//        };
//    }
}
