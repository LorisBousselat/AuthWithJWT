package LorisBousselat.AuthWithJWT.repository;

import LorisBousselat.AuthWithJWT.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String name);
}
