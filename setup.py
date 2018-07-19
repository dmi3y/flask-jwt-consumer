import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flask_jwt_consumer",
    version="0.0.3",
    author="Dmitrii Lapshukov",
    author_email="lapshukov@gmail.com",
    description="JWT consumer with multi public key support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dmi3y/flask-jwt-consumer",
    packages=setuptools.find_packages(),
    install_requires=['Flask', 'PyJWT', 'cryptography'],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
