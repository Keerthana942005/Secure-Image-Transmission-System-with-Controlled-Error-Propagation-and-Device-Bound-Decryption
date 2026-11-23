# Makefile for Secure Image Transmission System

.PHONY: test exp tables figures lint app clean all

PYTHON ?= python

test:
	$(PYTHON) -m unittest discover tests

exp:
	$(PYTHON) experiments/run_all.py

tables:
	$(PYTHON) scripts/make_tables.py

figures:
	$(PYTHON) scripts/make_figures.py

lint:
	$(PYTHON) scripts/lint_latex.py

app:
	$(PYTHON) -m streamlit run app.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete

all: test tables figures lint

