ALTER TABLE account
    ADD COLUMN security_question varchar(200);

ALTER TABLE account
    ADD COLUMN security_answer varchar(200);

ALTER TABLE account
    ADD COLUMN mfa_secret varchar(200);

ALTER TABLE account
    ADD COLUMN mfa_key_id varchar(200);

ALTER TABLE account
    ADD COLUMN mfa_enabled boolean;

ALTER TABLE account
    ADD COLUMN mfa_registered boolean;

ALTER TABLE account
    ADD COLUMN security_question_enabled boolean;