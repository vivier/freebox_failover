srpm:
	dnf install python3-pip dnf5-plugins python3-setuptools python3-wheel
	dnf builddep freebox-failover.spec
	pip install build
	python3 -m build --sdist
	rpmbuild --ta dist/freebox_failover-0.0.1.tar.gz --define "_srcrpmdir $(outdir)"
