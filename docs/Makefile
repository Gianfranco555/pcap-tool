HTML_DIR := _build

.PHONY: html
html:
	PYTHONPATH=../src ../pdoc --html pcap_tool -o $(HTML_DIR) --force

.PHONY: clean
clean:
	rm -rf $(HTML_DIR)
