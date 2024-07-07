package com.akshay.springsecurity.config;

import com.akshay.springsecurity.model.Authority;
import com.akshay.springsecurity.model.Customer;
import com.akshay.springsecurity.repo.CustomerRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
@EnableWebSecurity(debug = true)
public class CustomUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomerRepo customerRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        List<Customer> customers = customerRepo.findByEmail(username);
        if (customers == null || customers.get(0) == null) {
            throw new BadCredentialsException("No user registered with this email");
        }
        Customer customer = customers.get(0);
        List<GrantedAuthority> grantedAuthorities = getGrantedAuthorities(customer.getAuthorities());
        if (passwordEncoder.matches(password, customer.getPwd())) {
            return new UsernamePasswordAuthenticationToken(username, password, grantedAuthorities);
        } else {
            throw new BadCredentialsException("Invalid password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private List<GrantedAuthority> getGrantedAuthorities(Set<Authority> authorities) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (Authority authority : authorities) {
            grantedAuthorities.add(new SimpleGrantedAuthority(authority.getName()));
        }
        return grantedAuthorities;
    }
}
