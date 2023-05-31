from setuptools import setup, find_namespace_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

test_deps = ["pytest", "pytest-cov"]
setup(
    name="zepben.auth",
    version="0.10.0b4",
    description="Utilities for authenticating to the Evolve App Server and Energy Workbench Server",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zepben/zepben-auth-python",
    author="Ramon Bouckaert",
    author_email="ramon.bouckaert@zepben.com",
    package_dir={"": "src"},
    packages=find_namespace_packages(where="src"),
    python_requires='>=3.7',
    install_requires=[
        "requests>=2.26.0, <2.27.0",
        "urllib3>=1.26.6, <1.27.0",
        "PyJWT>=2.1.0, <2.2.0",
        "dataclassy==0.6.2"
    ],
    extras_require={
        "test": test_deps,
    }
)
