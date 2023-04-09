package com.projeto.oauth2withgooglegithub.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;

import static org.springframework.security.config.Customizer.*;

@Configuration
@Slf4j
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .formLogin(withDefaults())
                .oauth2Login(withDefaults())
                .authorizeHttpRequests(c -> c.anyRequest().authenticated())
                .build();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService inMemoryUsers(){
        InMemoryUserDetailsManager users = new InMemoryUserDetailsManager();
        var leandro = new User("leandro",passwordEncoder().encode("123456"), Collections.emptyList());
        var elaine = User.builder()
                .username("elaine")
                .password(passwordEncoder().encode("654321"))
                .roles("USER")
                .authorities("read")
                .build();

        users.createUser(leandro);
        users.createUser(elaine);

        return users;
    }

    @Bean
    ApplicationListener<AuthenticationSuccessEvent> sucessLoger(){
        return event -> {
            log.info("sucess: {}",event.getAuthentication());
        };
    }
}
