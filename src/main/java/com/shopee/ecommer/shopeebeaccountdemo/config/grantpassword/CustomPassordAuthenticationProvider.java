package com.shopee.ecommer.shopeebeaccountdemo.config.grantpassword;

import com.shopee.ecommer.shopeebeaccountdemo.entity.Account;
import com.shopee.ecommer.shopeebeaccountdemo.entity.CustomPasswordUser;
import com.shopee.ecommer.shopeebeaccountdemo.repository.AccountRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.security.Principal;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class CustomPassordAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final OAuth2AuthorizationService authorizationService;

    private final AccountRepository accountRepository;

    private final PasswordEncoder passwordEncoder;

    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private String username = "";
    private String password = "";
    private Set<String> authorizedScopes = new HashSet<>();

    public CustomPassordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                               OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                               AccountRepository accountRepository,
                                               PasswordEncoder passwordEncoder
    ) {

        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "TokenGenerator cannot be null");
        Assert.notNull(accountRepository, "accountRepository cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.accountRepository = accountRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        CustomPasswordAuthenticationToken customPasswordAuthenticationToken = (CustomPasswordAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(customPasswordAuthenticationToken);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        username = customPasswordAuthenticationToken.getUsername();
        password = customPasswordAuthenticationToken.getPassword();
        Account account = accountRepository.findByUsername(username);
        try {
            if (ObjectUtils.isEmpty(account)) {
                throw new UsernameNotFoundException("Access Denied " + username);
            }
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        if (!passwordEncoder.matches(password, account.getPassword()) || !account.getUsername().equalsIgnoreCase(username)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }
        Collection<GrantedAuthority> authorities = new HashSet<>();
        account.getRoleAccountList().forEach(auth -> authorities.add(new SimpleGrantedAuthority(auth.getCode())));
        authorizedScopes = authorities.stream()
                .map(scope -> scope.getAuthority())
                .filter(scope -> registeredClient.getScopes().contains(scope))
                .collect(Collectors.toSet());

        //-----------Create a new Security Context Holder Context----------
        OAuth2ClientAuthenticationToken oAuth2ClientAuthenticationToken = (OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        CustomPasswordUser customPasswordUser = new CustomPasswordUser(username, authorities);
        oAuth2ClientAuthenticationToken.setDetails(customPasswordUser);

        var newcontext = SecurityContextHolder.createEmptyContext();
        newcontext.setAuthentication(oAuth2ClientAuthenticationToken);
        SecurityContextHolder.setContext(newcontext);

        //-----------TOKEN BUILDERS----------
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizationGrant(customPasswordAuthenticationToken);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .attribute(Principal.class.getName(), clientPrincipal)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(new AuthorizationGrantType("custom_password"))
                .authorizedScopes(authorizedScopes);


        //-----------ACCESS TOKEN----------
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        //-----------REFRESH TOKEN----------
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return CustomPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
