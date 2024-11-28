import logging

import uvicorn


def main():
    from .app import package_name, settings_dependency

    settings = settings_dependency()
    log_level = logging.getLevelNamesMapping()[settings.log_level.upper()]

    uvicorn_log_config = {
        "version": 1,
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "rich.logging.RichHandler",
                "rich_tracebacks": True,
            }
        },
        "formatters": {
            "default": {
                "format": "%(message)s",
                "datefmt": "[%X]",
                "style": "%",
            }
        },
        "loggers": {
            "uvicorn": {
                "level": "INFO",
                "handlers": ["default"],
                "propagate": False,
            },
            package_name: {
                "level": log_level,
                "handlers": ["default"],
                "propagate": False,
            },
        },
        "root": {"handlers": ["default"]},
    }

    if log_level < logging.INFO:
        uvicorn_log_config["loggers"]["sqlalchemy.engine"] = {
            "level": log_level,
            "handlers": ["default"],
            "propagate": False,
        }

    uvicorn.run(
        f"{package_name}:app",
        host=str(settings.host),
        port=int(settings.port),
        reload=settings.reload,
        reload_includes=["*.py", "*.env"],
        log_config=uvicorn_log_config,
    )


if __name__ == "__main__":
    main()
