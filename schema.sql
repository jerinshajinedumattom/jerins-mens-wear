-- Jerin's Men's Wear - Relational Database Schema & Inventory Seed Script
-- Compatible with standard SQL. Dual-engine adaptation (MySQL / SQLite) is performed dynamically by the application.

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'customer',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Products Table
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    category VARCHAR(100) NOT NULL,
    image_url VARCHAR(500) NOT NULL,
    stock INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Shopping Cart Table
CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Orders Logging Table
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'Pending',
    total_amount DECIMAL(10, 2) NOT NULL,
    shipping_address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 5. Order Items Table
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL,
    price DECIMAL(10, 2) NOT NULL
);

-- 6. Security Event Auditing Table
CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(100) NOT NULL,
    username VARCHAR(255),
    details TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seed Initial Premium Fashion Catalog
-- Note: Insert statements ignore existing to prevent overwrites on application restarts.
INSERT OR IGNORE INTO products (id, name, description, price, category, image_url, stock) VALUES
(1, 'Egyptian Giza Cotton Shirt', 'Crafted from the rarest extra-long staple Egyptian Giza cotton, this formal shirt offers an ultra-soft handle, elegant drape, and a sophisticated semi-spread collar.', 12500.00, 'Shirts', 'https://images.unsplash.com/photo-1596755094514-f87e34085b2c?auto=format&fit=crop&q=80&w=600', 35),
(2, 'Royal Oxford Weave Shirt', 'A classic white shirt designed in a premium double-ply Royal Oxford weave. Features mother-of-pearl buttons and custom mitered double cuffs.', 14000.00, 'Shirts', 'https://images.unsplash.com/photo-1620012253295-c05518e99309?auto=format&fit=crop&q=80&w=600', 40),
(3, 'Savile Row Wool Tuxedo', 'Exquisite double-breasted tuxedo tailored from 100% Super 150s Merino wool. Adorned with silk satin peak lapels and a hand-canvas interior.', 145000.00, 'Suits', 'https://images.unsplash.com/photo-1594938298603-c8148c4dae35?auto=format&fit=crop&q=80&w=600', 12),
(4, 'Imperial Silk Blend Suit', 'A masterclass in modern luxury. This sharp two-button suit features a rich navy silk-wool blend, offering a subtle, refined lustre.', 165000.00, 'Suits', 'https://images.unsplash.com/photo-1593032465175-481ac7f401a0?auto=format&fit=crop&q=80&w=600', 15),
(5, 'Bespoke Cashmere Chinos', 'Sleek, slim-fit flat-front trousers woven from a luxurious cotton-cashmere blend for absolute comfort and a modern silhouette.', 28000.00, 'Trousers', 'https://images.unsplash.com/photo-1624378439575-d8705ad7ae80?auto=format&fit=crop&q=80&w=600', 25),
(6, 'Premium Italian Wool Trousers', 'Structured, light grey trousers in premium Italian virgin wool. Double-pleated with adjustable side tabs for standard tailored precision.', 24000.00, 'Trousers', 'https://images.unsplash.com/photo-1582562124811-c09040d0a901?auto=format&fit=crop&q=80&w=600', 30),
(7, 'Imperial Velvet Blazer', 'A stunning smoking jacket-style blazer crafted from deep emerald premium cotton velvet. Accented with a quilted satin collar and lining.', 75000.00, 'Blazers', 'https://images.unsplash.com/photo-1507679799987-c73779587ccf?auto=format&fit=crop&q=80&w=600', 8),
(8, 'Classic Tweed Herringbone Blazer', 'A rustic yet elegant autumnal blazer in classic Shetland herringbone wool tweed. Built with soft shoulders and leather football buttons.', 68000.00, 'Blazers', 'https://images.unsplash.com/photo-1555069513-f4b8f377941b?auto=format&fit=crop&q=80&w=600', 18);
