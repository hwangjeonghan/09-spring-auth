package com.ohgiraffers.security.config;


import com.ohgiraffers.security.config.handler.AuthFailHandler;
import com.ohgiraffers.security.user.model.dto.UserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AuthFailHandler failHandler;

    @Autowired
    public SecurityConfig(AuthFailHandler failHandler) {
        this.failHandler = failHandler;
    }

    /*
    * 비밀번호를 인코딩 하기 위한 bean
    * bcrtypt는 비밀번호 해싱에 가장 많이 사용되는 알고리즘 중 하나이다.
    *
    * */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // 암호화 방식중하나 비크립트 로 암호화 시키는것
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()); // 정적리소스는 제거해라
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->{
            auth.requestMatchers("/auth/login","user/signup","/auth/fail","/").permitAll(); // 4가지 요청리소스들이 들어올때 아무런권한이 필요없다.
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            auth.anyRequest().authenticated();
        }).formLogin(login ->{
            login.loginPage("/auth/login");
            login.usernameParameter("user"); // 전달되는 name 키값을 넣어줘야함
            login.passwordParameter("pass");
            login.defaultSuccessUrl("/",true);
            login.failureHandler(failHandler); // 로그인이 실패됐을때
        }).logout(logout ->{
            logout.logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout")); // 로그아웃요청들어오면 로그아웃요층으로 인식하겠다
            logout.deleteCookies("JSESSIONID"); // 로그아웃요청을 날리면 요걸 삭제하겠다 삭제하면 로그인된 권한 객체를 지워버린다
            logout.invalidateHttpSession(true); //세션을 강제로 만료처리하겠다
            logout.logoutSuccessUrl("/"); //로그아웃완료되면 어떤 url로 갈거냐

        }).sessionManagement(session ->{  //서버에서 세션관리어떻게 할것이냐
            session.maximumSessions(1); // 세션을 몇개 만들수있는지 설정해주는것   중복로그인을 설정하지않겠다해서 1개만 설정함
            session.invalidSessionUrl("/"); // 튕겼을때 어떤페이지를 보여줄것이냐 친구가 내 아이디를 로그인하면 내걸 로그아웃시킬거냐 친구걸 로그아웃시킬거냐
        }).csrf(csrf -> csrf.disable()); // disable을 활성하지 않겠다 (남이 나인척하며 요청을 막날릴수있다. 그걸 막아줄수있는데 비활성화 하겠다 지금은)


        return http.build();
    }
}
