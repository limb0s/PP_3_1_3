package ru.kata.spring.boot_security.demo.controllers;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.models.Role;
import ru.kata.spring.boot_security.demo.models.User;
import ru.kata.spring.boot_security.demo.repositories.RoleRepository;
import ru.kata.spring.boot_security.demo.services.UserService;

import java.security.Principal;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    @Autowired
    public AdminController(final UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping()
    public String admin(Model model, Principal principal) {
        User newUser = new User();
        newUser.setRoles(roleRepository.findAll().stream().collect(Collectors.toSet()));
        model.addAttribute("newUser", newUser);
        model.addAttribute("principalCurrentUser", principal.getName());
        model.addAttribute("currentUser", userService.findByUsername(principal.getName()));
        model.addAttribute("currentUserRoles", userService.findByUsername(principal.getName()).getAuthorities());
        model.addAttribute("users", userService.getUsers());
        model.addAttribute("roles", roleRepository.findAll());

        return "admin";
    }

    @PostMapping("/addUser")
    public String addUser(@ModelAttribute("user") User user) {
        userService.saveUser(user);
        return "redirect:/admin";
    }

    @GetMapping("/update/{id}")
    public String update(@PathVariable("id") long id, Model model) {
        if (userService.getUser(id) == null) {
            System.out.println("user not found");
        }
        User editUser = userService.getUser(id);
        model.addAttribute("editUser", editUser);
        return "admin";
    }

    @PostMapping("/update/{id}")
    public String updateUser(@PathVariable("id") long id, @ModelAttribute("user") User user, Principal principal, Authentication authentication) {
        Role adminRole = new Role("ROLE_ADMIN");
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        userService.updateUser(id, user);
        if (principal.getName().equals(userService.getUser(id).getUsername()) && !userService.getUser(id).getRoles().contains(adminRole)) {
                Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
                Authentication newAuthentication = new UsernamePasswordAuthenticationToken
                        (existingAuth.getPrincipal(), existingAuth.getCredentials(), user.getRoles());

                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(newAuthentication);
                SecurityContextHolder.setContext(context);
                return "redirect:/user";
            }

        return "redirect:/admin";
    }

    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable("id") long id, Principal principal) {
        if (principal.getName().equals(userService.getUser(id).getUsername())) {
            userService.deleteUser(id);
            return "redirect:/logout";
        }
        userService.deleteUser(id);
        return "redirect:/admin";
    }
}
