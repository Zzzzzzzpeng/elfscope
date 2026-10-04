PYTHON ?= python

.PHONY: test check install-run

test:
	$(PYTHON) -m pytest

check:
	$(PYTHON) -m compileall -q src
	$(PYTHON) -m pytest

install-run:
	$(PYTHON) -m pip install -e .
