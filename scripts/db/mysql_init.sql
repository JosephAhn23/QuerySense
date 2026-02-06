-- MySQL test database for QuerySense
-- Creates tables with realistic data for generating EXPLAIN plans

USE testdb;

-- Orders table (large, for testing full table scan detection)
CREATE TABLE orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    customer_id INT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    total DECIMAL(10, 2) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Order items (for testing join performance)
CREATE TABLE order_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    product_id INT NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    price DECIMAL(10, 2) NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders(id)
);

-- Products table
CREATE TABLE products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    price DECIMAL(10, 2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Stored procedure to generate sample data
DELIMITER //

CREATE PROCEDURE generate_test_data()
BEGIN
    DECLARE i INT DEFAULT 1;
    
    -- Generate users
    WHILE i <= 10000 DO
        INSERT INTO users (email, name, status) VALUES (
            CONCAT('user', i, '@example.com'),
            CONCAT('User ', i),
            IF(RAND() < 0.9, 'active', 'inactive')
        );
        SET i = i + 1;
    END WHILE;
    
    -- Generate products
    SET i = 1;
    WHILE i <= 1000 DO
        INSERT INTO products (name, category, price, stock) VALUES (
            CONCAT('Product ', i),
            ELT(MOD(i, 5) + 1, 'Electronics', 'Clothing', 'Books', 'Home', 'Other'),
            ROUND(RAND() * 1000, 2),
            FLOOR(RAND() * 1000)
        );
        SET i = i + 1;
    END WHILE;
    
    -- Generate orders (in batches for performance)
    SET i = 1;
    WHILE i <= 250000 DO
        INSERT INTO orders (customer_id, status, total, created_at) VALUES (
            FLOOR(RAND() * 9999) + 1,
            ELT(FLOOR(RAND() * 5) + 1, 'pending', 'processing', 'shipped', 'delivered', 'completed'),
            ROUND(RAND() * 500 + 10, 2),
            DATE_SUB(NOW(), INTERVAL FLOOR(RAND() * 365) DAY)
        );
        SET i = i + 1;
        
        -- Commit every 10k rows
        IF MOD(i, 10000) = 0 THEN
            COMMIT;
        END IF;
    END WHILE;
    
    -- Generate order items
    SET i = 1;
    WHILE i <= 500000 DO
        INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (
            FLOOR(RAND() * 249999) + 1,
            FLOOR(RAND() * 999) + 1,
            FLOOR(RAND() * 5) + 1,
            ROUND(RAND() * 100 + 5, 2)
        );
        SET i = i + 1;
        
        IF MOD(i, 10000) = 0 THEN
            COMMIT;
        END IF;
    END WHILE;
END //

DELIMITER ;

-- Generate data (this takes a few minutes)
-- CALL generate_test_data();

-- For faster setup, use this simpler version:
INSERT INTO users (email, name, status)
SELECT 
    CONCAT('user', seq, '@example.com'),
    CONCAT('User ', seq),
    IF(RAND() < 0.9, 'active', 'inactive')
FROM (
    SELECT @row := @row + 1 AS seq 
    FROM (SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) a,
         (SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) b,
         (SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) c,
         (SELECT 0 UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9) d,
         (SELECT @row := 0) r
    LIMIT 10000
) numbers;

-- Create indexes (but leave orders.status unindexed for testing)
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
CREATE INDEX idx_order_items_product_id ON order_items(product_id);
CREATE INDEX idx_products_category ON products(category);

-- Analyze tables
ANALYZE TABLE orders;
ANALYZE TABLE order_items;
ANALYZE TABLE products;
ANALYZE TABLE users;
