.PHONY: install lint test demo ui clean

install:
\tpython -m pip install -e .

lint:
\truff check .

test:
\tpytest -q

demo:
\tcirc run --input data/samples --output output/demo-run

ui:
\tstreamlit run ui/app.py

clean:
\tpython -c "import shutil; shutil.rmtree('output/demo-run', ignore_errors=True)"
