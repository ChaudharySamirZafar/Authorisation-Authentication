package codenemy.api.service;

import codenemy.api.model.Role;
import codenemy.api.model.User;

import java.util.List;

/**
 * @author samir.zafar
 * @version 1.0
 * @since 28/06/2022
 */
public interface IUserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
