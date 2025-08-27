# простая API для авторизации и регистрации
## Запуск:
1. клонируйте этот репозиторий `git clone https://github.com/BOPOH1243/ttFastapiAuthService.git` 
2. запустите docker-compose `sudo docker-compose up -d`
3. радуйтесь, всё должно запуститься на 80 порту `https://localhost/docs`
## особенности:
- всё максимально просто, документация есть по адресу `/docs`
- само приложение реализует oauth2-like алгоритм авторизации, но не полностью
- в докере есть nginx, с ним можно поиграться
- всё сдобрено тестами ~от отчаяния, я ловил баг, связанный с некорректной подписью токенов~
```
.
├── alembic
│   ├── env.py
│   ├── __pycache__
│   ├── README
│   ├── script.py.mako
│   └── versions
├── alembic.ini
├── app
│   ├── db.py
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── __pycache__
│   ├── routes
│   ├── schemas.py
│   ├── services.py
│   └── settings.py
├── docker-compose.yml
├── dockerfile
├── nginx.conf
├── README.md
├── requirements.txt
├── tests
│   ├── conftest.py
│   ├── __init__.py
│   ├── __pycache__
│   ├── test_auth.py
│   └── test_services.py
└── wait-for-it.sh

9 directories, 21 files
```