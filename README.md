# Shopee-be-account-demo

# Run docker 
# Step 1 build
docker build . -t quannguyen1999/shopee-be-account-demo
> or
mvn spring-boot:build-image

# Step 2 run 
docker run -d -p 8070:8070 quannguyen1999/shopee-be-account-demo
