# tests/test_services.py
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from jose import jwt, JWTError
import time

from app.services import (
    get_password_hash,
    verify_password,
    create_tokens,
    decode_token,
    pwd_context
)
from app.settings import settings


class TestPasswordFunctions:
    """Тесты для функций работы с паролями"""
    
    def test_get_password_hash_returns_string(self):
        """Тест что get_password_hash возвращает строку"""
        result = get_password_hash("test_password")
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_get_password_hash_different_for_same_input(self):
        """Тест что хеши разные для одного и того же пароля (из-за соли)"""
        password = "same_password"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        assert hash1 != hash2
    
    def test_verify_password_correct(self):
        """Тест что verify_password возвращает True для правильного пароля"""
        password = "test_password"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True
    
    def test_verify_password_incorrect(self):
        """Тест что verify_password возвращает False для неправильного пароля"""
        password = "test_password"
        wrong_password = "wrong_password"
        hashed = get_password_hash(password)
        assert verify_password(wrong_password, hashed) is False
    
    def test_verify_password_empty(self):
        """Тест работы с пустыми паролями"""
        hashed = get_password_hash("")
        assert verify_password("", hashed) is True
        assert verify_password("not_empty", hashed) is False


class TestTokenFunctions:
    """Тесты для функций работы с токенами"""
    
    @patch('app.services.settings')
    @patch('app.services.datetime')
    def test_create_tokens_returns_tuple_of_strings(self, mock_datetime, mock_settings):
        """Тест что create_tokens возвращает кортеж из двух строк"""
        # Мокируем настройки
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = "30"
        mock_settings.REFRESH_TOKEN_EXPIRE_MINUTES = "1440"
        mock_settings.SECRET_KEY = "test_secret_key"
        
        # Мокируем текущее время
        fixed_time = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.utcnow.return_value = fixed_time
        
        # Мокируем jwt.encode
        with patch('app.services.jwt.encode') as mock_encode:
            mock_encode.side_effect = ["access_token", "refresh_token"]
            
            access_token, refresh_token = create_tokens("test_user")
            
            assert isinstance(access_token, str)
            assert isinstance(refresh_token, str)
            assert access_token == "access_token"
            assert refresh_token == "refresh_token"
    
    @patch('app.services.settings')
    @patch('app.services.datetime')
    def test_create_tokens_correct_payload(self, mock_datetime, mock_settings):
        """Тест что create_tokens создает корректные payload"""
        # Мокируем настройки
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = "30"
        mock_settings.REFRESH_TOKEN_EXPIRE_MINUTES = "1440"
        mock_settings.SECRET_KEY = "test_secret_key"
        
        # Мокируем текущее время
        fixed_time = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.now.return_value = fixed_time
        
        # Мокируем jwt.encode и захватываем аргументы
        with patch('app.services.jwt.encode') as mock_encode:
            mock_encode.side_effect = lambda payload, *args, **kwargs: f"token_{payload['type']}"
            
            access_token, refresh_token = create_tokens("test_user")
            
            # Проверяем что encode вызывался дважды
            assert mock_encode.call_count == 2
            
            # Получаем аргументы вызовов
            calls = mock_encode.call_args_list
            
            # Проверяем access token payload
            access_payload = calls[0][0][0]
            assert access_payload["sub"] == "test_user"
            assert access_payload["type"] == "access"
            assert access_payload["exp"] == int((fixed_time + timedelta(minutes=30)).timestamp())
            
            # Проверяем refresh token payload
            refresh_payload = calls[1][0][0]
            assert refresh_payload["sub"] == "test_user"
            assert refresh_payload["type"] == "refresh"
            assert refresh_payload["exp"] == int((fixed_time + timedelta(minutes=1440)).timestamp())
    
    @patch('app.services.settings')
    def test_decode_token_success(self, mock_settings):
        """Тест успешного декодирования токена"""
        mock_settings.SECRET_KEY = "test_secret_key"
        
        test_payload = {"sub": "test_user", "exp": int(time.time()) + 3600, "type": "access"}
        
        with patch('app.services.jwt.decode') as mock_decode:
            mock_decode.return_value = test_payload
            
            result = decode_token("test_token")
            
            mock_decode.assert_called_once_with(
                "test_token", "test_secret_key", algorithms=["HS256"]
            )
            assert result == test_payload
    
    @patch('app.services.settings')
    def test_decode_token_jwt_error(self, mock_settings):
        """Тест обработки ошибки JWT при декодировании"""
        mock_settings.SECRET_KEY = "test_secret_key"
        
        with patch('app.services.jwt.decode') as mock_decode:
            mock_decode.side_effect = JWTError("Invalid token")
            
            with pytest.raises(JWTError):
                decode_token("invalid_token")
    
    @patch('app.services.settings')
    def test_create_and_decode_integration(self, mock_settings):
        """Интеграционный тест создания и декодирования токена"""
        mock_settings.SECRET_KEY = "test_secret_key_123"
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = "30"
        mock_settings.REFRESH_TOKEN_EXPIRE_MINUTES = "1440"
        
        # Создаем токены
        access_token, refresh_token = create_tokens("test_user")
        
        # Декодируем access token
        access_payload = decode_token(access_token)
        assert access_payload["sub"] == "test_user"
        assert access_payload["type"] == "access"
        
        # Декодируем refresh token
        refresh_payload = decode_token(refresh_token)
        assert refresh_payload["sub"] == "test_user"
        assert refresh_payload["type"] == "refresh"
    
    def test_create_tokens_different_types(self):
        """Тест что access и refresh токены разные"""
        with patch('app.services.settings') as mock_settings:
            mock_settings.SECRET_KEY = "test_secret_key"
            mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = "30"
            mock_settings.REFRESH_TOKEN_EXPIRE_MINUTES = "30"
            
            access_token, refresh_token = create_tokens("test_user")
            assert access_token != refresh_token


class TestEdgeCases:
    """Тесты крайних случаев"""
    
    def test_empty_password(self):
        """Тест работы с пустым паролем"""
        hashed = get_password_hash("")
        assert verify_password("", hashed) is True
    
    def test_special_characters_password(self):
        """Тест работы с паролем со специальными символами"""
        password = "!@#$%^&*()_+-=[]{}|;:,.<>?/`~"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True
    
    def test_long_password(self):
        """Тест работы с длинным паролем"""
        password = "a" * 1000  # Очень длинный пароль
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True
    
    @patch('app.services.settings')
    def test_create_tokens_empty_subject(self, mock_settings):
        """Тест создания токенов с пустым subject"""
        mock_settings.SECRET_KEY = "test_secret_key"
        mock_settings.ACCESS_TOKEN_EXPIRE_MINUTES = "30"
        mock_settings.REFRESH_TOKEN_EXPIRE_MINUTES = "1440"
        
        access_token, refresh_token = create_tokens("")
        assert isinstance(access_token, str)
        assert isinstance(refresh_token, str)