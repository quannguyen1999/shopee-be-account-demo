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