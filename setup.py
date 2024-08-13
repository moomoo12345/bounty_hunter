from setuptools import setup, find_packages

setup(
    name="bounty_hunter",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "beautifulsoup4",
        "dnspython",
        "asyncio",
    ],
    entry_points={
        "console_scripts": [
            "bounty_hunter=main:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A comprehensive web vulnerability scanning tool for bounty hunters",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bounty_hunter",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
