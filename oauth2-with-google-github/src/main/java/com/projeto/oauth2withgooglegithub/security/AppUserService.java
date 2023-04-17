package com.projeto.oauth2withgooglegithub.security;

import jakarta.annotation.PostConstruct;
import lombok.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Value
public class AppUserService implements UserDetailsService {
    PasswordEncoder passwordEncoder;
    Map<String,AppUser> users = new HashMap<>();
    DefaultOAuth2UserService oauth2Delegate = new DefaultOAuth2UserService();
    OidcUserService oidcDelegate = new OidcUserService();

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.get(username);
    }

    @PostConstruct
    private void createHardcodeUsers(){
        var leandro = AppUser.builder()
                .username("leandro")
                .provider(LoginProvider.APP)
                .password(passwordEncoder.encode("123456"))
                .authorities(List.of(new SimpleGrantedAuthority("read")))
                .build();

        var elaine = AppUser.builder()
                .username("elaine")
                .provider(LoginProvider.APP)
                .password(passwordEncoder.encode("654321"))
                .authorities(List.of(new SimpleGrantedAuthority("read")))
                .build();

        createUser(leandro);
        createUser(elaine);
    }

    private void createUser(AppUser user){
        users.putIfAbsent(user.getUsername(),user);
    }
}
