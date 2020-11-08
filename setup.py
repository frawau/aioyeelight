#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import setuptools

version = "0.1.0"

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aioyeelight",
    packages=["aioyeelight"],
    # packages=setuptools.find_packages(),
    version=version,
    author="François Wautier",
    author_email="francois@wautier.eu",
    description="API for local communication with Yeelight devices over a LAN with asyncio.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="http://github.com/frawau/aioyeelight",
    keywords=["yeelight", "light", "automation", "xiaomi"],
    license="MIT",
    install_requires=["aiozeroconf", "cryptography"],
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # Pick your license as you wish (should match "license" above)
        "License :: OSI Approved :: MIT License",
        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
    ],
    entry_points={"console_scripts": ["aioyeelight=aioyeelight.__main__:main"]},
    zip_safe=False,
)
