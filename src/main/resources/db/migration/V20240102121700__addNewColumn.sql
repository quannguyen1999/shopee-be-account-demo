ALTER TABLE account
    ADD COLUMN created date;
ALTER TABLE account
    ADD COLUMN updated date;
ALTER TABLE account
    ADD COLUMN user_created varchar(200);
ALTER TABLE account
    ADD COLUMN user_updated varchar(200);
ALTER TABLE account
    ADD COLUMN is_active boolean;