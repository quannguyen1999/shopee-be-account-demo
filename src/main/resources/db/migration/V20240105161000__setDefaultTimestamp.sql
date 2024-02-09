ALTER TABLE account
    ALTER COLUMN created set DEFAULT current_timestamp::timestamp;

ALTER TABLE account
    ALTER COLUMN updated set DEFAULT current_timestamp::timestamp;