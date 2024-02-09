update client
set redirect_uris = 'http://127.0.0.1:4200/,http://127.0.0.1:8080/login/oauth2/code/api-client-oidc,http://127.0.0.1:8080/authorized,http://127.0.0.1:8080,http://127.0.0.1:4200/home'
where client_id = 'admin';