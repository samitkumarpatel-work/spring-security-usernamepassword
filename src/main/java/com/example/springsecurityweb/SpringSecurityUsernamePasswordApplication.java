package com.example.springsecurityweb;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Collection;
import java.util.List;

@SpringBootApplication
@RequiredArgsConstructor
@Slf4j
public class SpringSecurityUsernamePasswordApplication {
	final UserRepository userRepository;
	final BCryptPasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityUsernamePasswordApplication.class, args);
	}

	@EventListener(ApplicationStartedEvent.class)
	void applicationStartedEvent() {
		userRepository.saveAll(
			List.of(
				new User(null, "one", passwordEncoder.encode("secret1")),
				new User(null, "two", passwordEncoder.encode("secret2"))
			)
		);
	}
}

@Configuration
@EnableWebSecurity
class SecurityConfig {

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	@SneakyThrows
	public SecurityFilterChain webMvcSecurityFilterChain(HttpSecurity http) {
		http
			.authorizeHttpRequests((requests) -> requests
					.requestMatchers("/signup", "/register").permitAll()
					.anyRequest().authenticated()
			)
			// Serve a custom login page
			.formLogin((form) -> form
					.loginPage("/login")
					.permitAll()
			)
			// Serve a default login page
			/*.formLogin(Customizer.withDefaults())*/;

		return http.build();
	}
}


@Configuration
class MvcConfig implements WebMvcConfigurer {
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/").setViewName("home");
		registry.addViewController("/hello").setViewName("hello");
	}
}

@Controller
@Slf4j
@RequiredArgsConstructor
class MvcController {

	final UserRepository userRepository;
	final BCryptPasswordEncoder passwordEncoder;

	@GetMapping("/login")
	public String login(Model model) {
		return "login";
	}

	@GetMapping("/greeting")
	public String greeting(@RequestParam(name="name", required=false, defaultValue="World") String name, Model model) {
		model.addAttribute("name", name);
		return "greeting";
	}

	@GetMapping("/signup")
	public String signupForm(Model model) {
		model.addAttribute("user", new User(null, null, null));
		return "signup";
	}

	@PostMapping("/register")
	public String greetingSubmit(@ModelAttribute User user, Model model) {
		log.info("USER: {}", user);
		try {
			var newUser = userRepository.save(
					new User(null, user.username(), passwordEncoder.encode(user.password()))
			);
			model.addAttribute("user", newUser);
			return "signup-result";
		} catch (RuntimeException r) {
			log.error("ERROR",r);
			model.addAttribute("errorMessage", r);
			return "signup-error";
		}
	}
}


@Table("users")
record User(@Id Integer id, String username, String password) implements UserDetails {
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return null;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return username;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}

interface UserRepository extends ListCrudRepository<User, Integer> {
	User findByUsername(String username);
}

@Service
@RequiredArgsConstructor
@Slf4j
class UserService implements UserDetailsService {
	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) {
		log.info("loadUserByUsername: {}", username);
		return userRepository.findByUsername(username);
	}
}