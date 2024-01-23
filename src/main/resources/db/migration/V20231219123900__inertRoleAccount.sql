insert into account(id, username, password, birthday, gender)
values (gen_random_uuid(), 'admin', 'admin', current_date, true) ON CONFLICT (username)
                                                                 DO NOTHING;

insert into account(id, username, password, birthday, gender)
values (gen_random_uuid(), 'employee_sam', 'employee_sam', current_date, true) ON CONFLICT (username)
                                                                               DO NOTHING;

insert into account(id, username, password, birthday, gender)
values (gen_random_uuid(), 'client_a', 'client_a', current_date, true) ON CONFLICT (username)
                                                                       DO NOTHING;

insert into account(id, username, password, birthday, gender)
values (gen_random_uuid(), 'client_b', 'client_b', current_date, true) ON CONFLICT (username)
                                                                       DO NOTHING;

insert into accountRoles(account_id, role_id)
values ((select id from account where username = 'admin'), (select code from RoleAccount where code = 'ADMIN'));

insert into accountRoles(account_id, role_id)
values ((select id from account where username = 'employee_sam'),
        (select code from RoleAccount where code = 'EMPLOYEE'));

insert into accountRoles(account_id, role_id)
values ((select id from account where username = 'client_a'), (select code from RoleAccount where code = 'CLIENT'));

insert into accountRoles(account_id, role_id)
values ((select id from account where username = 'client_b'), (select code from RoleAccount where code = 'CLIENT'));