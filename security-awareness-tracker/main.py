import json, argparse, logging, os
from analyser.awareness_analyser import AwarenessAnalyser
from reports.report_generator import ReportGenerator
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

def run(sims_file="data/simulations.json", training_file="data/training.json", output=None):
    print("[*] Security Awareness Tracker v1.0")
    with open(sims_file) as f: sims = json.load(f)
    with open(training_file) as f: training = json.load(f)
    print("[+] {} campaign(s) | {} employee record(s).".format(len(sims), len(training)))
    results = AwarenessAnalyser().analyse(sims, training)
    print()
    print(ReportGenerator().generate(results))
    if output:
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output,"w") as f: json.dump(results, f, indent=4)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--simulations", default="data/simulations.json")
    ap.add_argument("--training",    default="data/training.json")
    ap.add_argument("--output",      default="reports/awareness_report.json")
    args = ap.parse_args()
    run(args.simulations, args.training, args.output)
