from setuptools import setup, find_packages

setup(
    name="payguard",
    version="1.0.0",
    description="AI-powered phishing and scam detection for macOS",
    author="PayGuard",
    packages=find_packages(),
    package_data={
        "payguard": ["models/*.model"],
    },
    python_requires=">=3.9",
    install_requires=[
        "rumps>=0.4.0",
        "httpx>=0.24.0",
        "xgboost>=1.7.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "Pillow>=9.0.0",
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "payguard=payguard.detector:main",
        ],
    },
)
