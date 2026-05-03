package com.dev.security.service;

import com.dev.security.model.UserAuth;
import com.dev.security.repository.UserAuthRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// During the authentication the spring framework fetch the user details
// if fetches via loadUserByUsername method that's why we are implementing UserDetailsService
@Service
public class AuthService implements UserDetailsService {


    @Autowired
    private UserAuthRepository userAuthRepository;

    public void save(UserAuth userAuth)
    {
        userAuthRepository.save(userAuth);
    }

    @Override
    public UserAuth loadUserByUsername(String userName) throws UsernameNotFoundException {
        return userAuthRepository.findByEmail(userName).orElseThrow(()-> new UsernameNotFoundException("User not found"));
    }

}
