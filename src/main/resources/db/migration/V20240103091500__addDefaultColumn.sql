update account
set email = 'empty'
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update account
set avatar = 'https://w7.pngwing.com/pngs/152/155/png-transparent-male-man-person-business-avatar-icon.png'
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update account
set created = current_date
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update account
set updated = current_date
where username in ('admin', 'employee_sam', 'client_a', 'client_b');

update account
set is_active = true
where username in ('admin', 'employee_sam', 'client_a');

update account
set is_active = false
where username in ('client_b');

ALTER TABLE account
    ALTER COLUMN password SET DEFAULT 'no_pass';

ALTER TABLE account
    ALTER COLUMN created SET DEFAULT current_date;

ALTER TABLE account
    ALTER COLUMN updated SET DEFAULT current_date;

ALTER TABLE account
    ALTER COLUMN user_created SET DEFAULT 'admin';

ALTER TABLE account
    ALTER COLUMN user_updated SET DEFAULT 'admin';

ALTER TABLE account
    ALTER COLUMN is_active SET DEFAULT true;
