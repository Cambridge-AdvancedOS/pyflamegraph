SOURCES = $(wildcard *.py)
TESTS = $(wildcard tests/*.py)

all: lint test

run: $(SOURCES)
	python3.8 pyflamegraph.py tests/test_cases/simple.dtrace

# N.B. We run black on the test suite to format it, but we don't type check
# or lint it because that seems unnecessary
lint: black mypy pylint

black: $(SOURCES:.py=.py.black) $(TESTS:.py=.py.black)

%.py.black: %.py
	black $<
	touch $@

mypy: $(SOURCES:.py=.py.mypy)

%.py.mypy: %.py
	mypy $<
	touch $@

pylint: $(SOURCES:.py=.py.pylint)

%.py.pylint: %.py
	pylint $<
	touch $@

test: $(SOURCES) $(TESTS)
	pytest

clean:
	rm -f *.py.black
	rm -f *.py.mypy
	rm -f *.py.pylint
	rm -f tests/*.py.black
	rm -f tests/*.py.mypy
	rm -f tests/*.py.pylint
	rm -rf .mypy_cache
	rm -rf .pytest_cache
	rm -rf __pycache__
	rm -rf tests/__pycache__




#python3 flamegraph/prof.py

#python3 -m cProfile -o stacktrace.prof flamegraph/stacktrace.py | tee output

#python3 flamegraph/stacktrace.py | tee output
