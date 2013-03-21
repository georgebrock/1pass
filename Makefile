release:
	git tag `ENV/bin/python setup.py --version`
	ENV/bin/python setup.py sdist upload
