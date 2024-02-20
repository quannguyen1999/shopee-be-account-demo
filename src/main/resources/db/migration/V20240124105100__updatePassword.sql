ALTER TABLE account
ALTER
COLUMN password TYPE varchar(1000);

update account
set password = '$2a$10$H2fnzkVd05EUybKAAaI.lO0r.SYHCh1H9JVpFhiJ9Yv/Ne/QM8Diy'
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update client
set scopes = 'read,write'
where client_name = 'admin';

update client
set redirect_uris = 'http://127.0.0.1:4200/'
where client_name = 'admin';

update client
set client_secret = '$2a$10$H2fnzkVd05EUybKAAaI.lO0r.SYHCh1H9JVpFhiJ9Yv/Ne/QM8Diy'
where client_name = 'admin';

update client
set authorization_grant_types = 'authorization_code'
where client_name = 'admin';

