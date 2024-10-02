package ru.kata.spring.boot_security.demo.services;

import ru.kata.spring.boot_security.demo.models.User;

import java.util.List;

public interface UserService {
    List<User> getUsers();

    User getUser(Long id);

    void saveUser(User user);

    void deleteUser(Long id);

    void updateUser(Long id, User user);

    User findByUsername(String username);
}