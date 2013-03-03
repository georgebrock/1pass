release:
	git tag `ENV/bin/python setup.py --verion`
	ENV/bin/python setup.py sdist upload
