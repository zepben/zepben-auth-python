from setuptools import setup, find_namespace_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

test_deps = ["pytest", "pytest-cov"]
setup(
    name="zepben.auth",
    version="0.2.0b2",
    description="Utilities for authenticating to the Evolve App Server and Energy Workbench Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bitbucket.org/zepben/zepben-auth-python",
    author="Ramon Bouckaert",
    author_email="ramon.bouckaert@zepben.com",
    package_dir={"": "src"},
    packages=find_namespace_packages(where="src"),
    python_requires='>=3.7',
    install_requires=[
        "requests==2.25.1",
        "urllib3==1.26.6",
        "PyJWT==2.1.0",
        "grpcio==1.36.0",
        "dataclassy==0.6.2"
    ],
    extras_require={
        "test": test_deps,
    }
)
