ALTER TABLE category
    ADD COLUMN created date;
ALTER TABLE category
    ADD COLUMN updated date;
ALTER TABLE category
    ADD COLUMN user_created varchar(200);
ALTER TABLE category
    ADD COLUMN user_updated varchar(200);

ALTER TABLE category
    ALTER COLUMN created SET DEFAULT current_date;

ALTER TABLE category
    ALTER COLUMN updated SET DEFAULT current_date;

ALTER TABLE category
    ALTER COLUMN user_created SET DEFAULT 'admin';

ALTER TABLE category
    ALTER COLUMN user_updated SET DEFAULT 'admin';

ALTER TABLE category ALTER COLUMN created TYPE timestamp USING created::timestamp;
ALTER TABLE category ALTER COLUMN updated TYPE timestamp USING updated::timestamp;
ALTER TABLE category
    ALTER COLUMN created set DEFAULT current_timestamp::timestamp;

ALTER TABLE category
    ALTER COLUMN updated set DEFAULT current_timestamp::timestamp;