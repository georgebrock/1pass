import os

from setuptools import setup


VERSION = "0.1.6"

def readme():
    """ Load the contents of the README file """
    readme_path = os.path.join(os.path.dirname(__file__), "README.txt")
    with open(readme_path, "r") as f:
        return f.read()

setup(
    name="1pass",
    version=VERSION,
    author="George Brocklehurst",
    author_email="george.brocklehurst@gmail.com",
    description="A Python library and command line interface for 1Password",
    long_description=readme(),
    install_requires=["simple-pbkdf2", "PyCrypto"],
    license="MIT",
    url="http://github.com/georgebrock/1pass",
    classifiers=[],
    packages=["onepassword"],
    scripts=["bin/1pass"],

    tests_require=["nose", "mock"],
    test_suite="nose.collector",
)
