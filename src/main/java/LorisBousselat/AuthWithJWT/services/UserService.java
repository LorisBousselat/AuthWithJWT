package LorisBousselat.AuthWithJWT.services;

import LorisBousselat.AuthWithJWT.domain.AppUser;
import LorisBousselat.AuthWithJWT.domain.Role;

import java.util.List;

public interface UserService {
    AppUser saveUser(AppUser user);
    Role save(Role role);
    void addRoleToUser(String username, String roleName);
    AppUser getUser(String username);
    List<AppUser> getUsers();
}
