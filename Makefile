release:
	git tag --sign `ENV/bin/python setup.py --version`
	ENV/bin/python setup.py sdist upload
