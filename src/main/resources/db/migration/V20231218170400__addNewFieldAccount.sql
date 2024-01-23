ALTER TABLE account
    ADD IF NOT EXISTS birthday date;

ALTER TABLE account
    add IF NOT EXISTS gender boolean default false;

ALTER TABLE account
    ADD IF NOT EXISTS email varchar (200);

ALTER TABLE account
    ADD IF NOT EXISTS avatar varchar;

CREATE TABLE IF NOT EXISTS RoleAccount
(
    code
    varchar
    PRIMARY
    KEY,
    name
    VARCHAR
(
    20
)
    );


