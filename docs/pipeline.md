# Pipeline Architecture

This project now includes a lightweight pipeline framework for chaining
processing, analysis and reporting steps.  Pipelines can be configured
programmatically or loaded from a YAML/JSON file.

## Building a Pipeline

```python
from pcap_tool.pipeline import Pipeline, BaseProcessor

pipeline = Pipeline()
# pipeline.add_processor(MyProcessor())
# pipeline.add_analyzer(MyAnalyzer())
# pipeline.add_reporter(MyReporter())
result = pipeline.run(input_data)
```

The ``on_progress`` callback passed to ``run`` receives the current
step and total number of steps so UIs can display status information.

## Configuration File Example

```yaml
processors:
  - name: pcap_tool.processors.tcp_processor.TCPProcessor
analyzers:
  - name: pcap_tool.analyze.performance.PerformanceAnalyzer
reporters:
  - name: pcap_tool.reporting.summary.SummaryReporter
```

Load the configuration using ``Pipeline.from_config("config.yaml")``.
