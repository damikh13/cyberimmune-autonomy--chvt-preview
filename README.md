# Задача для регионального этапа соревнований по кибериммунной автономности Чемпионата Высоких Технологий 2025

Рекомендуем использовать редактор VS Code для работы с проектом.

Рекомендуемые расширения для VS Code:

-   Python
-   Jupyter
-   Docker

При использовании github codespace следует установить следующие пакеты:

-   docker-compose

Начните работу с файла cyberimmunity--autonomous-car-m1.ipynb - это интерактивный jupyter блокнот, в котором сведена вся необходимая информация для участия в соревнованиях.

Открывать этот блокнот и начинать работу следует после установки всех пакетов и расширений, указанных выше.

По всем вопросам просьба обращаться по адресу cyberimmunity-edu@kaspersky.com

# Генерация сертификатов для работы TLS терминатора

Создаём директорию для хранения сертификатов и ключей:

```bash
mkdir certs
cd certs
```

Создаём приватный ключ для Root CA:

```bash
openssl genrsa -out ca_root.key 4096
```

Создаём самоподписанный сертификат для Root CA:

```bash
openssl req -x509 -new -nodes \
  -key ca_root.key \
  -sha256 \
  -days 3650 \
  -out ca_root.crt \
  -subj "/CN=My Test CA/O=MyOrg/OU=Dev"
```

Создаём приватный ключ для сервера (TLS терминатора):

```bash
openssl genrsa -out server.key 2048
```

Создаём запрос на сертификат для сервера:

```bash
openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/CN=my.server.local/O=MyOrg/OU=Services"
```

Создаём сертификат для сервера, подписанный Root CA:

```bash
openssl x509 -req \
  -in server.csr \
  -CA ca_root.crt \
  -CAkey ca_root.key \
  -CAcreateserial \
  -out server.crt \
  -days 365 \
  -sha256
```

Можем проверить, что сертификат корректно подписан:

```bash
openssl verify -CAfile ca_root.crt server.crt
```

Должно получиться что-то вроде:

```
server.crt: OK
```

# Тестирование
Все тесты основных компонент выполнены в файле `test_tls_mission.py`.
Запуск тестов проивзодится при помощи команды:
```
pytest -q
```