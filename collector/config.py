import os

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

MYSQL_HOST = os.getenv("MYSQL_HOST", "db")
MYSQL_USER = os.getenv("MYSQL_USER", "siem")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "siempass")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "siemdb")

DB_POOL_MIN_CACHED = int(os.getenv("DB_POOL_MIN_CACHED", "2"))
DB_POOL_MAX_CACHED = int(os.getenv("DB_POOL_MAX_CACHED", "10"))
DB_POOL_MAX_CONNECTIONS = int(os.getenv("DB_POOL_MAX_CONNECTIONS", "20"))

JWT_SECRET = os.getenv("JWT_SECRET", "super-tajny-klucz-mini-siem-p2")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 480
PASSWORD_SALT = b"mini-siem-static-salt-p2"
