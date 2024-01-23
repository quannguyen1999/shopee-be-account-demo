ALTER TABLE qa_shopee.account
    ADD COLUMN created date;
ALTER TABLE qa_shopee.account
    ADD COLUMN updated date;
ALTER TABLE qa_shopee.account
    ADD COLUMN user_created varchar(200);
ALTER TABLE qa_shopee.account
    ADD COLUMN user_updated varchar(200);
ALTER TABLE qa_shopee.account
    ADD COLUMN is_active boolean;