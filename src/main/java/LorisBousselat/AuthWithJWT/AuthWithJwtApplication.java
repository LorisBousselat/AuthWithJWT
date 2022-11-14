package LorisBousselat.AuthWithJWT;

import LorisBousselat.AuthWithJWT.domain.AppUser;
import LorisBousselat.AuthWithJWT.domain.ERoles;
import LorisBousselat.AuthWithJWT.domain.Role;
import LorisBousselat.AuthWithJWT.services.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class AuthWithJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthWithJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner run(UserService userService){
		return arg ->{
			String selena_username = "selena";
			String john_username = "john";
			String will_username = "will";
			String jim_username = "jim";

			userService.save(new Role(null, ERoles.ROLE_USER.name()));
			userService.save(new Role(null, ERoles.ROLE_ADMIN.name()));
			userService.save(new Role(null, ERoles.ROLE_SUPER_ADMIN.name()));
			userService.save(new Role(null, ERoles.ROLE_MANAGER.name()));

			userService.saveUser(new AppUser(null, "Jhon Travolta", john_username, "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Will Smith", will_username, "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Jim Carry", jim_username, "1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Selena Gomez", selena_username, "1234", new ArrayList<>()));

			userService.addRoleToUser(john_username, ERoles.ROLE_USER.name());
			userService.addRoleToUser(john_username, ERoles.ROLE_MANAGER.name());
			userService.addRoleToUser(will_username, ERoles.ROLE_MANAGER.name());
			userService.addRoleToUser(jim_username, ERoles.ROLE_ADMIN.name());
			userService.addRoleToUser(selena_username, ERoles.ROLE_USER.name());
			userService.addRoleToUser(selena_username, ERoles.ROLE_ADMIN.name());
			userService.addRoleToUser(selena_username, ERoles.ROLE_SUPER_ADMIN.name());
		};
	}

}
