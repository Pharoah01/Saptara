from setuptools import setup, find_packages

setup(
    name="saptara",
    version="1.0.0",
    description="Automated Web Application Vulnerability Assessment Framework",
    py_modules=["cli"],
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[
        "click>=8.0.0",
        "httpx>=0.24.0",
        "rich>=13.0.0",
        "python-dotenv>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "saptara=cli:cli",
        ],
    },
)
