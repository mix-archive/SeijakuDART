import uvicorn


def main():
    from .app import package_name, settings_dependency

    settings = settings_dependency()
    uvicorn_log_config = {
        "version": 1,
        "disable_existing_loggers": False,
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
        "root": {"level": settings.log_level.upper(), "handlers": ["default"]},
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
