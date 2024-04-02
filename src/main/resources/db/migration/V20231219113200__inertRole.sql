CREATE TABLE accountRoles
(
    account_id UUID references account (id),
    role_id    varchar references RoleAccount (code),
    PRIMARY KEY (account_id, role_id)
);

