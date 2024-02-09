update client
set scopes = 'read,write,openid'
where client_id = 'admin';

update client
set authorization_grant_types = 'authorization_code,refresh_token'
where client_id = 'admin';

update client
set token_settings = '{"access-token-time-to-live": 1, "authorization-code-time-to-live": 1}}'
where client_id = 'admin';

update client
set redirect_uris = 'http://127.0.0.1:4200/,http://127.0.0.1:8080/login/oauth2/code/api-client-oidc,http://127.0.0.1:8080/authorized,http://127.0.0.1:8080'
where client_id = 'admin';