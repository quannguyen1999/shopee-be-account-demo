package com.shopee.ecommer.shopeebeaccountdemo.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.shopee.ecommer.shopeebeaccountdemo.constant.ConstantUtil;
import com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.encrypt.AesBytesEncryptor;
import org.springframework.security.crypto.encrypt.BytesEncryptor;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.util.ObjectUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.shopee.ecommer.shopeebeaccountdemo.constant.PathApi.AUTHORIZE_PATH;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

//    @Autowired
//    CustomAuthenticationFailed customAuthenticationFailed;

    @Value("${custom-security.issuer}")
    private String issuer;

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // Allow all origins, methods, and headers. This is just an example.
        config.addAllowedOrigin("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http
                .addFilterBefore(new SessionInvalidationFilter(), AbstractPreAuthenticatedProcessingFilter.class)
                .cors()
                .and()
                .csrf(AbstractHttpConfigurer::disable)
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults())
                .and()
                .exceptionHandling(e -> e.authenticationEntryPoint(new
                        LoginUrlAuthenticationEntryPoint(PathApi.LOGIN_PATH))
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/css/**",
                                "/image/**",
                                "/registration",
                                "/authenticator",
                                "/security-question"
                        )
                        .permitAll() // Permit access to CSS resources
                        .anyRequest().authenticated()
                )
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin().loginPage(PathApi.LOGIN_PATH).permitAll().successHandler(
                        new MFAHandlerSuccess(PathApi.AUTHENTICATOR_PATH, "ROLE_MFA_REQUIRED")
                )
                .and().build();
    }

    public class SessionInvalidationFilter extends OncePerRequestFilter {
        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            if (request.getRequestURI().equals(AUTHORIZE_PATH)) {
                Object result = request.getSession().getAttribute(ConstantUtil.ATTRIBUTE_MFA);
                if (ObjectUtils.isEmpty(result)) {
                    // Invalidate session if the request is to the authorization endpoint
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.invalidate();
                    }
                } else {
                    request.getSession().removeAttribute(ConstantUtil.ATTRIBUTE_MFA);
                }
            }
            filterChain.doFilter(request, response);
        }
    }

    @Bean
    AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }


    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    BytesEncryptor bytesEncryptor(@Value("${jwt.secret.key}") String secret) {
        SecretKey secretKey = new SecretKeySpec(Base64.getDecoder().decode(secret.trim()), "AES");
        BytesKeyGenerator ivGenerator = KeyGenerators.secureRandom(12);
        return new AesBytesEncryptor(secretKey, ivGenerator, AesBytesEncryptor.CipherAlgorithm.GCM);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .authorizationEndpoint(AUTHORIZE_PATH)
                .tokenEndpoint("/oauth2/token")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                context.getClaims().claim("Test", "Test Access Token");
                Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities)
                        .claim("user", principal.getName());
            }
        };
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }


    public static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
    }

    static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    //Set timeout session
    @Bean
    public HttpSessionListener httpSessionListener() {
        return new HttpSessionListener() {
            @Override
            public void sessionCreated(HttpSessionEvent event) {
                HttpSession session = event.getSession();
                // Set the session timeout to 30 seconds
                session.setMaxInactiveInterval(30);
            }

            @Override
            public void sessionDestroyed(HttpSessionEvent event) {
                // Handle session destroyed event if needed
                event.getSession().invalidate();
            }
        };
    }


}
