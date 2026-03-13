"""
Centralized logging configuration
"""

import sys
import logging
from pathlib import Path
from typing import Optional
from loguru import logger
from rich.console import Console
from rich.logging import RichHandler


class InterceptHandler(logging.Handler):
    """Intercept standard logging and redirect to loguru"""
    
    def emit(self, record):
        # Get corresponding Loguru level if it exists
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno

        # Find caller from where originated the logged message
        frame, depth = logging.currentframe(), 2
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1

        logger.opt(depth=depth, exception=record.exc_info).log(level, record.getMessage())


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    service_name: str = "security-test",
    enable_rich: bool = True
) -> None:
    """
    Setup centralized logging configuration
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        service_name: Service name for log formatting
        enable_rich: Enable rich console output
    """
    
    # Remove default loguru handler
    logger.remove()
    
    # Console handler with rich formatting
    if enable_rich:
        console = Console()
        logger.add(
            RichHandler(console=console, rich_tracebacks=True),
            level=level,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                   "<level>{level: <8}</level> | "
                   "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                   "<level>{message}</level>",
            colorize=True
        )
    else:
        logger.add(
            sys.stdout,
            level=level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
            colorize=False
        )
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            log_file,
            level=level,
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
            rotation="10 MB",
            retention="7 days",
            compression="gz"
        )
    
    # Intercept standard logging
    logging.basicConfig(handlers=[InterceptHandler()], level=0, force=True)
    
    # Set service context
    logger.configure(extra={"service": service_name})


def get_logger(name: str) -> "logger":
    """
    Get a logger instance for a specific module
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    return logger.bind(module=name)


# Service-specific loggers
def get_scanner_logger():
    """Get logger for scanner service"""
    return get_logger("scanner")


def get_validator_logger():
    """Get logger for validator service"""
    return get_logger("validator")


def get_simulator_logger():
    """Get logger for simulator service"""
    return get_logger("simulator")


def get_orchestrator_logger():
    """Get logger for orchestrator service"""
    return get_logger("orchestrator")