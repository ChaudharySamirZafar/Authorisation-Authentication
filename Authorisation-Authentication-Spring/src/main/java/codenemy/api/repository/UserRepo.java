package codenemy.api.repository;

import codenemy.api.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author samir.zafar
 * @version 1.0
 * @since 28/06/2022
 */
public interface UserRepo extends JpaRepository<User, Integer> {
    User findByUsername(String username);
}
