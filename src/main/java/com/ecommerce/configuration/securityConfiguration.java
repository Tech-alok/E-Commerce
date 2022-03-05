package com.ecommerce.configuration;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.util.AntPathMatcher;

@Configuration
@EnableWebSecurity
public class securityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http
		     .authorizeRequests()
		     .antMatchers("/","/shop/**","/register","/h2-console/**").permitAll()
		     .antMatchers("/admin/**").hasRole("ADMIN")
		     .anyRequest()
		     .authenticated()
		     .and()
		     .formLogin()
		     .loginPage("/login")
		     .permitAll()
		     .failureUrl("/login?error= true")
		     .defaultSuccessUrl("/")
		     .usernameParameter("email")
		     .passwordParameter("password")
		     .and()
		     .oauth2Login()
		     .loginPage("/login")
		     .successHandler(googleOAuth2SuccessHandler)
		     .and()
		     .logout()
		     .logoutRequestMacther(new AntPathMatcher("/logout"))
		     .logoutSuccessUrl("login")
		     .invalidateHttpSession(true)
		     .deleteCookies("JSESSIONID")
		     .and()
		     .csrf()
		     .disable();
		
		
		http.headers().frameOptions().disable();
	}
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws IOException{
		auth.userDetailsService(customUserDetailService);
	}
	
	@Override
	public void configure(WebSecurity web) throws IOException{
		web.ignoring().antMatchers("/resources/**, /static/**, /image/**, /productImages/**", "/css/**","/js/**");
	}
	
	
	
	
}
