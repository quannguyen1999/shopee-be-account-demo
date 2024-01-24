create table client
(
    id                            varchar(255) not null,
    authorization_grant_types     varchar(1000),
    client_authentication_methods varchar(1000),
    client_id                     varchar(255),
    client_id_issued_at           timestamp(6) with time zone,
    client_name                   varchar(255),
    client_secret                 varchar(255),
    client_secret_expires_at      timestamp(6) with time zone,
    client_settings               varchar(2000),
    redirect_uris                 varchar(1000),
    scopes                        varchar(1000),
    token_settings                varchar(2000),
    primary key (id)
);

INSERT INTO client (id,
                    authorization_grant_types,
                    client_authentication_methods,
                    client_id,
                    client_id_issued_at,
                    client_name,
                    client_secret,
                    client_secret_expires_at,
                    client_settings,
                    redirect_uris,
                    scopes,
                    token_settings)
VALUES (gen_random_uuid(),
        'authorization_code,implicit',
        'client_secret_basic',
        'admin',
        CURRENT_TIMESTAMP,
        'admin',
        'admin',
        CURRENT_TIMESTAMP + INTERVAL '1' DAY, -- Assuming client_secret_expires_at is one day from now
        '{"key":"value"}',
        'http://localhost:4200/',
        'read write',
        '{"token_key":"token_value"}');

