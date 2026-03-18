import argparse
from dia.analyzer import Analyzer
from dia.reporter import Reporter

parser = argparse.ArgumentParser()
parser.add_argument("--offline", action="store_true")
parser.add_argument("--container")
args = parser.parse_args()

if args.offline:
    from dia.offline_collector import OfflineCollector as Collector
else:
    from dia.collector import Collector

collector = Collector()
analyzer = Analyzer()
reporter = Reporter()

names = [args.container] if args.container else collector.list_containers()

for name in names:
    data = collector.inspect_container(name)
    report = analyzer.analyze(data)
    print(reporter.to_json(report))
