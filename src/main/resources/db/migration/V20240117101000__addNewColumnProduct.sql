ALTER TABLE product
    ADD COLUMN created date;
ALTER TABLE product
    ADD COLUMN updated date;
ALTER TABLE product
    ADD COLUMN user_created varchar(200);
ALTER TABLE product
    ADD COLUMN user_updated varchar(200);

ALTER TABLE product
    ALTER COLUMN created SET DEFAULT current_date;

ALTER TABLE product
    ALTER COLUMN updated SET DEFAULT current_date;

ALTER TABLE product
    ALTER COLUMN user_created SET DEFAULT 'admin';

ALTER TABLE product
    ALTER COLUMN user_updated SET DEFAULT 'admin';

ALTER TABLE product ALTER COLUMN created TYPE timestamp USING created::timestamp;
ALTER TABLE product ALTER COLUMN updated TYPE timestamp USING updated::timestamp;
ALTER TABLE product
    ALTER COLUMN created set DEFAULT current_timestamp::timestamp;

ALTER TABLE product
    ALTER COLUMN updated set DEFAULT current_timestamp::timestamp;