
update qa_shopee.client 
set client_authentication_methods  = 'client_secret_basic,client_secret_post'
where client_id  = 'admin'