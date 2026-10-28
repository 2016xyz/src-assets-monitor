# ========================================================
# SRC 资产检测站 (SRC Assets Monitor) - 生产级 PHP 8.2 FPM 镜像
# ========================================================
FROM php:8.2-fpm-alpine

# 设置国内/官方镜像源加速并安装系统依赖
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories || true \
    && apk update \
    && apk add --no-cache \
        bash \
        curl \
        curl-dev \
        libpng-dev \
        libxml2-dev \
        oniguruma-dev \
        freetype-dev \
        libjpeg-turbo-dev \
        tzdata \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        pdo \
        pdo_mysql \
        sockets \
        curl \
        mbstring \
        fileinfo \
        opcache \
        bcmath

# 设置时区为亚洲/上海
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 设置 PHP 生产配置
RUN { \
        echo 'opcache.memory_consumption=128'; \
        echo 'opcache.interned_strings_buffer=8'; \
        echo 'opcache.max_accelerated_files=4000'; \
        echo 'opcache.revalidate_freq=2'; \
        echo 'opcache.fast_shutdown=1'; \
        echo 'opcache.enable_cli=1'; \
    } > /usr/local/etc/php/conf.d/opcache-recommended.ini \
    && { \
        echo 'upload_max_filesize = 50M'; \
        echo 'post_max_size = 50M'; \
        echo 'memory_limit = 256M'; \
        echo 'max_execution_time = 300'; \
        echo 'date.timezone = Asia/Shanghai'; \
    } > /usr/local/etc/php/conf.d/custom-php.ini

WORKDIR /var/www/html

EXPOSE 9000
CMD ["php-fpm"]
