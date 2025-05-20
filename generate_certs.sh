#!/bin/bash

set -e  # Прекратить выполнение при ошибке

# Создаём директорию для хранения сертификатов и ключей
mkdir -p certs
cd certs

echo "✅ Директория certs создана."

# Создаём приватный ключ для Root CA
openssl genrsa -out ca_root.key 4096
echo "🔑 Приватный ключ для Root CA создан: ca_root.key"

# Создаём самоподписанный сертификат для Root CA
openssl req -x509 -new -nodes \
  -key ca_root.key \
  -sha256 \
  -days 3650 \
  -out ca_root.crt \
  -subj "/CN=My Test CA/O=MyOrg/OU=Dev"
echo "📄 Самоподписанный сертификат Root CA создан: ca_root.crt"

# Создаём приватный ключ для сервера
openssl genrsa -out server.key 2048
echo "🔐 Приватный ключ сервера создан: server.key"

# Создаём запрос на сертификат для сервера
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/CN=my.server.local/O=MyOrg/OU=Services"
echo "📑 Сертификатный запрос сервера создан: server.csr"

# Подписываем серверный сертификат Root CA
openssl x509 -req \
  -in server.csr \
  -CA ca_root.crt \
  -CAkey ca_root.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -sha256
echo "✅ Сертификат сервера подписан Root CA: server.crt"

# Проверяем подпись сертификата
openssl verify -CAfile ca_root.crt server.crt
echo "🔍 Сертификат сервера успешно проверен."

echo "🎉 Все сертификаты и ключи успешно созданы в директории certs/"

