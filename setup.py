from setuptools import setup, find_packages

setup(
    name="ssh-sk-attest",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.109.2",
        "uvicorn>=0.27.1",
        "fido2>=1.1.2",
        "cryptography>=42.0.2",
        "requests>=2.31.0",
        "python-multipart>=0.0.9",
        "sqlalchemy>=2.0.27",
    ],
    entry_points={
        'console_scripts': [
            'ssh-sk-attest=ssh_sk_attest.cli:main',
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="Library for verifying SSH SK attestations",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ssh-sk-attest",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
) 