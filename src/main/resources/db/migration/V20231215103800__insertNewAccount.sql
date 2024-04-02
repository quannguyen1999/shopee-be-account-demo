-- Constraints for username
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'username'
    ) THEN
        ALTER TABLE Account ADD CONSTRAINT username UNIQUE (username);
    END IF;
END $$;