import os

from setuptools import setup


VERSION = "0.2.1"

def readme():
    """ Load the contents of the README file """
    readme_path = os.path.join(os.path.dirname(__file__), "README.txt")
    with open(readme_path, "r") as f:
        return f.read()

setup(
    name="1pass",
    version=VERSION,
    author="George Brocklehurst",
    author_email="george@georgebrock.com",
    description="A Python library and command line interface for 1Password",
    long_description=readme(),
    install_requires=["M2Crypto", "fuzzywuzzy"],
    license="MIT",
    url="http://github.com/georgebrock/1pass",
    classifiers=[],
    packages=["onepassword"],
    entry_points={'console_scripts': ['1pass=onepassword.cli:cli']},

    tests_require=["nose", "mock"],
    test_suite="nose.collector",
)
