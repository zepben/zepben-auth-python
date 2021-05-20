from setuptools import setup, find_namespace_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="zepben.auth",
    version="0.1",
    description="Utilities for authenticating to the Evolve App Server and Energy Workbench Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://bitbucket.org/zepben/zepben-auth-python",
    author="Ramon Bouckaert",
    author_email="ramon.bouckaert@zepben.com",
    package_dir={"": "src"},
    packages=find_namespace_packages(where="src"),
    python_requires='>=3.7'
)
