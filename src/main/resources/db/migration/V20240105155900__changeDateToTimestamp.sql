ALTER TABLE account ALTER COLUMN created TYPE timestamp USING created::timestamp;
ALTER TABLE account ALTER COLUMN updated TYPE timestamp USING updated::timestamp;
ALTER TABLE account ALTER COLUMN birthday TYPE timestamp USING created::timestamp;