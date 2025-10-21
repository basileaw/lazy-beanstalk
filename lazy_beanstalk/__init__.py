# __init__.py

"""
Lazy Beanstalk - Simple AWS Elastic Beanstalk deployment tool.

A pip-installable package that provides both CLI and programmatic API
for deploying Python applications to AWS Elastic Beanstalk.
"""

__version__ = "2.0.0"

# Public API imports
from .ship import ship
from .secure import secure
from .shield import shield
from .scrap import scrap
from .config import ConfigurationError, DeploymentError

__all__ = [
    "__version__",
    "ship",
    "secure",
    "shield",
    "scrap",
    "ConfigurationError",
    "DeploymentError",
]
