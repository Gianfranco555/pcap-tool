# AGENTS.md

 
test: |
  # Run the full pytest suite quietly (dots only)
  pytest -q
  
lint: |
  flake8 src/ tests/
