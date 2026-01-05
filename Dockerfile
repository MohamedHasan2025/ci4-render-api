# Use official PHP + Apache image
FROM php:8.2-apache

# Set working directory
WORKDIR /var/www/html

# Install system dependencies and PHP extensions required by CI4
RUN apt-get update && apt-get install -y \
    git \
    unzip \
    libicu-dev \
    libxml2-dev \
    libzip-dev \
    && docker-php-ext-install intl mbstring mysqli pdo pdo_mysql zip \
    && a2enmod rewrite

# Set Apache document root to public/
ENV APACHE_DOCUMENT_ROOT /var/www/html/public

# Update Apache config to use public/ as root
RUN sed -ri -e 's!/var/www/html!/var/www/html/public!g' /etc/apache2/sites-available/*.conf \
    && sed -ri -e 's!/var/www/!/var/www/html/public!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Copy composer.lock and composer.json first (for caching)
COPY composer.json composer.lock /var/www/html/

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Install PHP dependencies without dev packages
RUN composer install --no-dev --optimize-autoloader --no-interaction || true

# Copy all project files
COPY . /var/www/html

# Give proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Expose port 80
EXPOSE 80

# Start Apache in the foreground
CMD ["apache2-foreground"]
