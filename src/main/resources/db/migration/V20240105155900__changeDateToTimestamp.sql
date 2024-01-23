ALTER TABLE qa_shopee.account ALTER COLUMN created TYPE timestamp USING created::timestamp;
ALTER TABLE qa_shopee.account ALTER COLUMN updated TYPE timestamp USING updated::timestamp;
ALTER TABLE qa_shopee.account ALTER COLUMN birthday TYPE timestamp USING created::timestamp;