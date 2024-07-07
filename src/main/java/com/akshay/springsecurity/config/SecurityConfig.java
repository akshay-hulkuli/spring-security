package com.akshay.springsecurity.config;

import com.akshay.springsecurity.filter.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        csrfTokenRequestAttributeHandler.setCsrfRequestAttributeName("_csrf");

        http
                // Responsible for generating JSession ID
//                .securityContext(httpSecuritySecurityContextConfigurer ->
//                        httpSecuritySecurityContextConfigurer.requireExplicitSave(false))
//                .sessionManagement(httpSecuritySessionManagementConfigurer ->
//                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration corsConfiguration = new CorsConfiguration();
                    corsConfiguration.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    corsConfiguration.setAllowedMethods(Collections.singletonList("*"));
                    corsConfiguration.setAllowCredentials(true);
                    corsConfiguration.setAllowedHeaders(Collections.singletonList("*"));
                    corsConfiguration.setExposedHeaders(List.of("Authorization"));
                    return corsConfiguration;
                }))
                .csrf(httpSecurityCsrfConfigurer ->
                        httpSecurityCsrfConfigurer
                                .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                                .ignoringRequestMatchers("/contact", "/register")
                                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .authorizeRequests(authorizeRequests ->
                                authorizeRequests
//                                .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                                .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
//                                .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
//                                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                                        .requestMatchers("/myAccount").hasRole("USER")
                                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                                        .requestMatchers("/myCards").hasRole("USER")
                                        .requestMatchers("/myLoans").authenticated()
                                        .requestMatchers("/user").authenticated()
                                        .requestMatchers("/notices", "/contact", "/register").permitAll()
                )
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new CSRFCookieFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    /****  InMemoryUserDetailsManager   */
    /*
      There are two approaches to create users in Spring Security:
       1. using withDefaultPasswordEncoder() method
       2. using withUsername() and password() methods here we need to explicitly provide the password encoder.
     */

//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder().username("admin").password("admin").roles("USER").build();
//        UserDetails user = User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build();
//        return new InMemoryUserDetailsManager(admin, user);
//    }
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails admin = User.withUsername("admin").password("admin").authorities("admin").build();
//        UserDetails user = User.withUsername("user").password("user").authorities("read").build();
//        return new InMemoryUserDetailsManager(admin, user);
//    }
//
//    @Bean
//    public PasswordEncoder getPasswordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }


    /*****
     * This is using JDBC User Details manager.
     * We need to provide the DataSource to the JdbcUserDetailsManager.
     * The JdbcUserDetailsManager will use the DataSource to query the users and authorities.
     * We need to create 2 tables users and authorities.
     * These are the standard tables that Spring Security uses to store the user information.
     */
//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        return new JdbcUserDetailsManager(dataSource);
//    }
//
    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


//    @Bean
//    public SecurityFilterChain denyAllRequests(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().denyAll());
//        return httpSecurity.build();
//    }
//
//    @Bean
//    public SecurityFilterChain permitAllRequests(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll());
//        return httpSecurity.build();
//    }
}
