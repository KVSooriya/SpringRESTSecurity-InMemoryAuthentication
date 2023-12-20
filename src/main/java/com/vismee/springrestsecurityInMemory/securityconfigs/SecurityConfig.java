package com.vismee.springrestsecurityInMemory.securityconfigs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig
{

    // In-Memory authentication - one way of defining users, passwords and roles for security implementation
    @Bean
    public InMemoryUserDetailsManager userDetailsManager()
    {
        UserDetails abi = User.builder().
                          username("abi").
                          password("{noop}memory123").   // {noop} - no operation ie. plain text password
                          roles("EMPLOYEE").
                          build();

        UserDetails annu = User.builder().
                           username("annu").
                           password("{noop}memory123").
                           roles("MANAGER").
                           build();

        UserDetails sooriya = User.builder().
                              username("sooriya").
                              password("{noop}memory123").
                              roles("ADMIN").
                              build();

        return new InMemoryUserDetailsManager(abi,annu,sooriya);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception
    {
        // Restrict access based on roles
        http.authorizeHttpRequests(configurer ->
                configurer.
                requestMatchers(HttpMethod.GET,"/api/employees").hasAnyRole("EMPLOYEE","MANAGER","ADMIN").
                requestMatchers(HttpMethod.GET,"/api/employees/**").hasAnyRole("EMPLOYEE","MANAGER","ADMIN").
                requestMatchers(HttpMethod.POST,"/api/employees").hasAnyRole("MANAGER","ADMIN").
                requestMatchers(HttpMethod.PUT,"/api/employees").hasAnyRole("MANAGER","ADMIN").
                requestMatchers(HttpMethod.DELETE,"/api/employees/**").hasRole("ADMIN")
        );

        // Use HTTP Basic Authentication
        http.httpBasic(Customizer.withDefaults());

        // disable Cross Site Request Forgery (CSRF)
        // Not required for Stateless Rest API's that use POST, PUT, DELETE, PATCH ..
        http.csrf(csrf -> csrf.disable());
        return http.build();
    }
}
