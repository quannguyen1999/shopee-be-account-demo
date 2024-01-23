update account
set user_created = 'admin'
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update account
set user_updated = 'admin'
where username in ('admin', 'employee_sam', 'client_a', 'client_b');
