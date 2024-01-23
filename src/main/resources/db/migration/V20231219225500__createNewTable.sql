CREATE TABLE Category (
    ID UUID PRIMARY KEY,
    name VARCHAR(200),
    image VARCHAR
 );

CREATE TABLE Product  (
    ID UUID PRIMARY KEY,
    name VARCHAR(200),
    image VARCHAR,
    quantity numeric,
    price numeric,
    discount numeric,
    category_id UUID,
    FOREIGN KEY (category_id) REFERENCES Category(ID)
);

