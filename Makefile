.PHONY: setup

setup:
	python -m pip install --upgrade pip
	pip install -e .[dev]
	pip install -r requirements.txt
