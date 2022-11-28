package com.lemakhno.threatanalyzer.service;

import static java.util.Objects.isNull;

import java.util.Collections;

import javax.transaction.Transactional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.lemakhno.threatanalyzer.entity.AppUserEntity;
import com.lemakhno.threatanalyzer.repository.AppUserRepository;

@Service
@Transactional
public class AppUserService implements UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Getting User by username: {}", username);
        AppUserEntity userEntity = appUserRepository.findByUsername(username);
        if (isNull(userEntity)) throw new UsernameNotFoundException("Coult not find User with username: " + username);
        return new User(userEntity.getUsername(), userEntity.getPassword(), Collections.emptyList());
    }
}
