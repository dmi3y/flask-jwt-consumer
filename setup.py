import setuptools

import os
import sys

from setuptools.command.install import install


with open("README.md", "r") as fh:
    long_description = fh.read()

VERSION = "1.0.1"

class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our version"""
    description = 'verify that the git tag matches our version'

    def run(self):
        tag = os.getenv('CIRCLE_TAG')

        if tag != VERSION:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                tag, VERSION
            )
            sys.exit(info)


setuptools.setup(
    name="flask_jwt_consumer",
    version=VERSION,
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
    cmdclass={
        'verify': VerifyVersionCommand,
    },
)
