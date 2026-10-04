import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "django-insecure-dev-only-change-me")
DEBUG = env_bool("DJANGO_DEBUG", True)
FRONT_DOMAIN = os.getenv("FRONT_DOMAIN", "").strip().lower()
API_DOMAIN = os.getenv("API_DOMAIN", "").strip().lower()
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,0.0.0.0,testserver")
if API_DOMAIN and API_DOMAIN not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(API_DOMAIN)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "corsheaders",
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "scanner_engine",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DB_ENGINE = os.getenv("DB_ENGINE", "django.db.backends.sqlite3")
DATABASES = {
    "default": {
        "ENGINE": DB_ENGINE,
        "NAME": os.getenv("DB_NAME", str(BASE_DIR / "db.sqlite3")),
    }
}
if DB_ENGINE != "django.db.backends.sqlite3":
    DATABASES["default"].update(
        {
            "USER": os.getenv("DB_USER", ""),
            "PASSWORD": os.getenv("DB_PASSWORD", ""),
            "HOST": os.getenv("DB_HOST", ""),
            "PORT": os.getenv("DB_PORT", ""),
            "CONN_MAX_AGE": int(os.getenv("DB_CONN_MAX_AGE", "60")),
        }
    )

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
HTTPS_PORT = int(os.getenv("HTTPS_PORT", "443"))
default_frontend_origins: list[str] = []
if FRONT_DOMAIN:
    http_port_suffix = "" if HTTP_PORT == 80 else f":{HTTP_PORT}"
    https_port_suffix = "" if HTTPS_PORT == 443 else f":{HTTPS_PORT}"
    default_frontend_origins = [
        f"http://{FRONT_DOMAIN}{http_port_suffix}",
        f"https://{FRONT_DOMAIN}{https_port_suffix}",
    ]
configured_frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip().rstrip("/")
FRONTEND_ORIGIN = configured_frontend_origin or (default_frontend_origins[-1] if default_frontend_origins else "")
CORS_ALLOWED_ORIGINS = list(
    dict.fromkeys(
        env_list("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
        + default_frontend_origins
        + ([configured_frontend_origin] if configured_frontend_origin else [])
    )
)
CSRF_TRUSTED_ORIGINS = list(
    dict.fromkeys(
        env_list("CSRF_TRUSTED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
        + default_frontend_origins
        + ([configured_frontend_origin] if configured_frontend_origin else [])
    )
)

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
    "DEFAULT_PARSER_CLASSES": ["rest_framework.parsers.JSONParser"],
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv("JWT_ACCESS_MINUTES", "30"))),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv("JWT_REFRESH_DAYS", "7"))),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
}

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/1")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_TASK_TRACK_STARTED = True
TOOL_CRAWLER_INTERVAL_SECONDS = int(os.getenv("TOOL_CRAWLER_INTERVAL_SECONDS", "21600"))
CELERY_BEAT_SCHEDULE = {
    "crawl-tool-updates": {
        "task": "scanner_engine.tasks.crawl_tool_updates_task",
        "schedule": TOOL_CRAWLER_INTERVAL_SECONDS,
    }
}

SCANNER_RUN_INLINE = env_bool("SCANNER_RUN_INLINE", True)
SCANNER_MOCK_MODE = env_bool("SCANNER_MOCK_MODE", False)
SCANNER_WORK_DIR = Path(os.getenv("SCANNER_WORK_DIR", str(BASE_DIR / "var" / "scans")))
TOOL_LOCK_DIR = Path(os.getenv("TOOL_LOCK_DIR", str(BASE_DIR / "var" / "tool_locks")))
YARA_RULES_DIR = Path(os.getenv("YARA_RULES_DIR", str(BASE_DIR / "var" / "yara_rules")))
YARA_RULE_REPOS = env_list(
    "YARA_RULE_REPOS",
    "https://github.com/Yara-Rules/rules,https://github.com/Neo23x0/signature-base",
)
MAX_UPLOAD_SIZE = int(os.getenv("MAX_UPLOAD_SIZE", str(100 * 1024 * 1024)))

FILE_SANDBOX_ENABLED = env_bool("FILE_SANDBOX_ENABLED", True)
FILE_SANDBOX_MAX_UPLOAD_MB = int(os.getenv("FILE_SANDBOX_MAX_UPLOAD_MB", "50"))
FILE_SANDBOX_STORAGE_DIR = Path(os.getenv("FILE_SANDBOX_STORAGE_DIR", str(BASE_DIR / "var" / "file_sandbox")))
FILE_SANDBOX_MAX_UPLOAD_SIZE = FILE_SANDBOX_MAX_UPLOAD_MB * 1024 * 1024

CLAMAV_ENABLED = env_bool("CLAMAV_ENABLED", True)
CLAMSCAN_BIN = os.getenv("CLAMSCAN_BIN", "clamscan")
FRESHCLAM_BIN = os.getenv("FRESHCLAM_BIN", "freshclam")
YARA_ENABLED = env_bool("YARA_ENABLED", True)
YARA_BIN = os.getenv("YARA_BIN", "yara")
EXIFTOOL_ENABLED = env_bool("EXIFTOOL_ENABLED", True)
EXIFTOOL_BIN = os.getenv("EXIFTOOL_BIN", "exiftool")
PDFINFO_ENABLED = env_bool("PDFINFO_ENABLED", True)
PDFINFO_BIN = os.getenv("PDFINFO_BIN", "pdfinfo")

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", not DEBUG)
CSRF_COOKIE_SECURE = env_bool("CSRF_COOKIE_SECURE", not DEBUG)
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"

LOG_DIR = Path(os.getenv("LOG_DIR", str(BASE_DIR / "var" / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", str(LOG_DIR / "app.log"))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"()": "scanner_engine.logging.StructuredJsonFormatter"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "json",
            "filename": LOG_FILE_PATH,
            "maxBytes": 10 * 1024 * 1024,
            "backupCount": 5,
        },
    },
    "root": {
        "handlers": ["console", "file"],
        "level": os.getenv("LOG_LEVEL", "INFO"),
    },
    "loggers": {
        "django.request": {"level": "WARNING", "propagate": True},
        "scanner_engine": {"level": os.getenv("SCANNER_LOG_LEVEL", "INFO"), "propagate": True},
    },
}
