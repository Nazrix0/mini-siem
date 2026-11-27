import time
from typing import Optional

import pymysql
from dbutils.pooled_db import PooledDB

from config import (
    DB_POOL_MAX_CACHED,
    DB_POOL_MAX_CONNECTIONS,
    DB_POOL_MIN_CACHED,
    MYSQL_DATABASE,
    MYSQL_HOST,
    MYSQL_PASSWORD,
    MYSQL_USER,
)
from security import hash_password

_db_pool: Optional[PooledDB] = None


def _create_pool() -> PooledDB:
    return PooledDB(
        creator=pymysql,
        mincached=DB_POOL_MIN_CACHED,
        maxcached=DB_POOL_MAX_CACHED,
        maxconnections=DB_POOL_MAX_CONNECTIONS,
        blocking=True,
        ping=1,
        host=MYSQL_HOST,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DATABASE,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def get_db():
    """Zwraca połączenie z puli PooledDB (conn.close() oddaje je z powrotem do puli)."""
    global _db_pool
    if _db_pool is None:
        _db_pool = _create_pool()
    return _db_pool.connection()


def init_db():
    """Inicjalizuje pulę połączeń oraz schemat bazy MySQL z ponawianiem po starcie."""
    global _db_pool
    for attempt in range(10):
        try:
            _db_pool = _create_pool()
            conn = _db_pool.connection()
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS users (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(64) UNIQUE NOT NULL,
                            password_hash VARCHAR(128) NOT NULL,
                            role VARCHAR(32) DEFAULT 'analyst'
                        );
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS device_tokens (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            username VARCHAR(64) NOT NULL,
                            fcm_token VARCHAR(512) UNIQUE NOT NULL,
                            updated_at VARCHAR(64) NOT NULL
                        );
                        """
                    )
                    cur.execute(
                        """
                        CREATE TABLE IF NOT EXISTS alerts (
                            id INT AUTO_INCREMENT PRIMARY KEY,
                            timestamp VARCHAR(64),
                            source_ip VARCHAR(64),
                            alert_type VARCHAR(64),
                            description TEXT,
                            status VARCHAR(32) DEFAULT 'NEW',
                            updated_at VARCHAR(64),
                            asset_id VARCHAR(128) NULL,
                            latitude DOUBLE NULL,
                            longitude DOUBLE NULL,
                            reported_by VARCHAR(64) NULL
                        );
                        """
                    )
                    for stmt in [
                        "ALTER TABLE alerts ADD COLUMN status VARCHAR(32) DEFAULT 'NEW'",
                        "ALTER TABLE alerts ADD COLUMN updated_at VARCHAR(64)",
                        "ALTER TABLE alerts ADD COLUMN asset_id VARCHAR(128) NULL",
                        "ALTER TABLE alerts ADD COLUMN latitude DOUBLE NULL",
                        "ALTER TABLE alerts ADD COLUMN longitude DOUBLE NULL",
                        "ALTER TABLE alerts ADD COLUMN reported_by VARCHAR(64) NULL",
                        "CREATE INDEX idx_alerts_updated_at ON alerts (updated_at)",
                    ]:
                        try:
                            cur.execute(stmt)
                        except pymysql.err.OperationalError as exc:
                            # 1060 = Duplicate column, 1061 = Duplicate key/index name
                            if exc.args[0] not in (1060, 1061):
                                raise

                    default_users = [
                        ("admin", hash_password("admin123"), "admin"),
                        ("analyst", hash_password("analyst123"), "analyst"),
                    ]
                    for username, pwd_hash, role in default_users:
                        cur.execute(
                            "INSERT IGNORE INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
                            (username, pwd_hash, role),
                        )
            finally:
                conn.close()
            print(
                f"[Collector] Pula MySQL (max={DB_POOL_MAX_CONNECTIONS}) i schemat bazy gotowe."
            )
            return
        except Exception as exc:
            print(f"[Collector init_db próba {attempt + 1}/10] {exc}")
            time.sleep(2)
