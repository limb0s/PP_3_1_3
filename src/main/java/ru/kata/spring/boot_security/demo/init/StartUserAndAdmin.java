package ru.kata.spring.boot_security.demo.init;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.repositories.RoleRepository;
import ru.kata.spring.boot_security.demo.services.UserService;

import javax.annotation.PostConstruct;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class StartUserAndAdmin {

    private final RoleRepository roleRepository;
    private final UserService userService;

    @Autowired
    public StartUserAndAdmin(RoleRepository roleRepository, UserService userService) {
        this.roleRepository = roleRepository;
        this.userService = userService;
    }

    @PostConstruct
    private  void init(){
        roleRepository.save(new Role(1L,"ROLE_ADMIN"));
        roleRepository.save(new Role(2L,"ROLE_USER"));
        Set<Role> adminRole = roleRepository.findById(1L).stream().collect(Collectors.toSet());
        Set<Role> userRole = roleRepository.findById(2L).stream().collect(Collectors.toSet());
        userService.saveUser(new User("Elena",30,"admin","admin",adminRole));
        userService.saveUser(new User("Oleg",21,"user","user",userRole));
    }
}
