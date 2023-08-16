package codenemy.api.repository;

import codenemy.api.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author samir.zafar
 * @version 1.0
 * @since 28/06/2022
 */
public interface RoleRepo extends JpaRepository<Role, Integer> {
    Role findByName(String name);
}
