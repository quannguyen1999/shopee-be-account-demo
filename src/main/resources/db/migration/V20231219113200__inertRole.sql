insert into roleaccount(code, name)
values ('ADMIN', 'ADMIN') on conflict (code) do nothing;

insert into roleaccount(code, name)
values ('EMPLOYEE', 'EMPLOYEE') on conflict (code) do nothing;

insert into roleaccount(code, name)
values ('CLIENT', 'CLIENT') on conflict (code) do nothing;

CREATE TABLE accountRoles
(
    account_id UUID references account (id),
    role_id    varchar references RoleAccount (code),
    PRIMARY KEY (account_id, role_id)
);

