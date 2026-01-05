# Use official PHP image with Apache
FROM php:8.2-apache

# Enable required PHP extensions
RUN docker-php-ext-install mysqli pdo pdo_mysql

# Enable mod_rewrite for CodeIgniter
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy the entire project into container
COPY . /var/www/html

# Set correct permissions (optional)
RUN chown -R www-data:www-data /var/www/html
RUN chmod -R 755 /var/www/html

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer
RUN composer install --no-dev --optimize-autoloader

# Expose port
EXPOSE 8080

# Start Apache in foreground
CMD ["apache2-foreground"]
