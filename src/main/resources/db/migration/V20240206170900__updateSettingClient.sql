update qa_shopee.client
set redirect_uris = 'http://127.0.0.1:4200/,https://oauthdebugger.com/debug,http://127.0.0.1:4200/home,http://127.0.0.1:8080/login/oauth2/code/api-client-oidc,http://127.0.0.1:8080,http://localhost:4200/home'
where client_id = 'admin'
