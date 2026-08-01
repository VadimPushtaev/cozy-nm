.PHONY: pre-commit

pre-commit:
	poetry run pytest -q
