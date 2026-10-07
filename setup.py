"""
Setup configuration for SentinelAI
100% Cross-Platform (Windows, Linux, macOS)
"""
from setuptools import setup, find_packages
from pathlib import Path

this_dir = Path(__file__).parent
readme = (this_dir / "README.md").read_text(encoding="utf-8") if (this_dir / "README.md").exists() else ""

setup(
    name="sentinelai",
    version="2.4.0",
    description="AI-Powered Offensive Security, Vulnerability Assessment & Penetration Testing Arsenal",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="SentinelAI Team",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "rich>=13.0.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "pydantic>=2.0.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.20.0",
        "sqlalchemy>=2.0.0",
        "aiosqlite>=0.20.0",
        "certifi",
        "pyyaml",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "sentinelai=sentinelai.cli.main:main",
            "sentinel=sentinelai.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
)
