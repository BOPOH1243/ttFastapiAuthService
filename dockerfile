FROM python:3.12-slim

# Устанавливаем зависимости для компиляции пакетов
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Создаем рабочую директорию
WORKDIR /code

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Копируем весь проект
COPY . .

# Устанавливаем переменную окружения для Python path
ENV PYTHONPATH=/code
