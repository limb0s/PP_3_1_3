package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import ru.kata.spring.boot_security.demo.services.UserService;

import java.security.Principal;

@Controller
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(final UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user")
    public String user(Model model, Principal principal) {
        model.addAttribute("currentUser", principal.getName());
        model.addAttribute("principalCurrentUser", principal.getName());
        model.addAttribute("currentUserRoles", userService.findByUsername(principal.getName()).getAuthorities());
        model.addAttribute("user", userService.findByUsername(principal.getName()));
        return "user";
    }
}
