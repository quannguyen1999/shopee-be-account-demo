update account
set mfa_enabled = true
where username = 'admin';

update account
set mfa_registered = false
where username = 'admin';

update account
set security_question_enabled = false
where username = 'admin';

update account
set security_answer = 'fuck'
where username = 'admin';
