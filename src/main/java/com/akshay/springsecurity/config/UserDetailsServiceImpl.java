package com.akshay.springsecurity.config;

import com.akshay.springsecurity.model.Customer;
import com.akshay.springsecurity.repo.CustomerRepo;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

// keeping this commented because we have defined our own authentication provider
//@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final CustomerRepo customerRepo;

    public UserDetailsServiceImpl(CustomerRepo customerRepo) {
        this.customerRepo = customerRepo;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<Customer> customers = customerRepo.findByEmail(username);
        if (customers.get(0) == null) {
            throw new UsernameNotFoundException("User not found");
        }
        Customer customer = customers.get(0);
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority(customer.getRole()));
        return new User(customer.getEmail(), customer.getPwd(), grantedAuthorities);
    }
}
