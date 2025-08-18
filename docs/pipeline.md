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
  - name: pcap_tool.analysis.performance.PerformanceAnalyzer
reporters:
  - name: pcap_tool.reporting.summary.SummaryReporter
```

Note: analyzers are referenced via the `pcap_tool.analysis` namespace. The older `pcap_tool.analyze` paths continue to work but are deprecated.

Load the configuration using ``Pipeline.from_config("config.yaml")``.

### Security Considerations

Components are imported dynamically based on the ``name`` fields in the
configuration file. **Only load configuration files from trusted sources**.
An attacker who controls the file could point to malicious Python classes,
leading to arbitrary code execution. The loader validates that each component
inherits from the expected base class, but it cannot prevent execution of
arbitrary import paths.
