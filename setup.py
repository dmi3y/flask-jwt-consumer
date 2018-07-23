import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="flask_jwt_consumer",
    version="1.0.0",
    author="Dmitrii Lapshukov",
    author_email="lapshukov@gmail.com",
    description="Flask JWT consumer with multi public key support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=["jwt", "jwt-consumer", "jwt-validation", "authentication", "autherization", "multi-issuer"],
    url="https://github.com/dmi3y/flask-jwt-consumer",
    packages=setuptools.find_packages(),
    install_requires=['Flask', 'PyJWT', 'cryptography'],
    classifiers=(
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)
