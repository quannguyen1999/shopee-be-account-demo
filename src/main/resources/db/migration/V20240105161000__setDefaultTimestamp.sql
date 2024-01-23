ALTER TABLE qa_shopee.account
    ALTER COLUMN created set DEFAULT current_timestamp::timestamp;

ALTER TABLE qa_shopee.account
    ALTER COLUMN updated set DEFAULT current_timestamp::timestamp;