from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import List

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.preprocessing import MultiLabelBinarizer


def _parse_labels(raw: str) -> List[str]:
  if not raw:
    return []
  tokens = [token.strip() for token in raw.replace(";", ",").split(",")]
  return [token for token in tokens if token]


def load_dataset(path: Path) -> tuple[list[str], list[list[str]], list[list[str]]]:
  descriptions: list[str] = []
  cwe_labels: list[list[str]] = []
  capec_labels: list[list[str]] = []

  with path.open("r", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    for row in reader:
      descriptions.append(row.get("description", "").strip())
      cwe_labels.append(_parse_labels(row.get("cwe") or row.get("cwes") or ""))
      capec_labels.append(_parse_labels(row.get("capec") or row.get("capecs") or ""))

  if not descriptions:
    raise ValueError("Dataset is empty – expected at least one row")

  return descriptions, cwe_labels, capec_labels


def build_model(
  descriptions: list[str],
  label_sets: list[list[str]],
  max_features: int,
  ngram_max: int,
  n_jobs: int,
):
  vectorizer = TfidfVectorizer(
    max_features=max_features,
    ngram_range=(1, ngram_max),
    lowercase=True,
    token_pattern=r"[A-Za-z0-9_\-]+",
  )
  features = vectorizer.fit_transform(descriptions)

  binarizer = MultiLabelBinarizer()
  target = binarizer.fit_transform(label_sets)

  classifier = OneVsRestClassifier(
    LogisticRegression(max_iter=500, solver="lbfgs"),
    n_jobs=n_jobs if n_jobs > 0 else None,
  )
  classifier.fit(features, target)

  return vectorizer, classifier, binarizer


def main() -> None:
  parser = argparse.ArgumentParser(description="Retrain threat-model artifacts.")
  parser.add_argument("--dataset", type=Path, required=True, help="CSV file with description,cwe,capec columns")
  parser.add_argument("--output", type=Path, required=True, help="Directory where pickles will be written")
  parser.add_argument("--max-features", type=int, default=25000, help="Max TF-IDF features")
  parser.add_argument("--ngram-max", type=int, default=2, help="Max n-gram length")
  parser.add_argument("--jobs", type=int, default=-1, help="Parallel jobs for OneVsRestClassifier")
  args = parser.parse_args()

  descriptions, cwe_labels, capec_labels = load_dataset(args.dataset)
  output_dir = args.output
  output_dir.mkdir(parents=True, exist_ok=True)

  print(f"Training on {len(descriptions)} CVE descriptions…")
  vectorizer, cwe_model, cwe_binarizer = build_model(
    descriptions, cwe_labels, args.max_features, args.ngram_max, args.jobs
  )
  _, capec_model, capec_binarizer = build_model(
    descriptions, capec_labels, args.max_features, args.ngram_max, args.jobs
  )

  joblib.dump(vectorizer, output_dir / "vectorizer.pkl")
  joblib.dump(cwe_model, output_dir / "cwe_model.pkl")
  joblib.dump(cwe_binarizer, output_dir / "cwe_binarizer.pkl")
  joblib.dump(capec_model, output_dir / "capec_model.pkl")
  joblib.dump(capec_binarizer, output_dir / "capec_binarizer.pkl")

  (output_dir / "metadata.json").write_text(
    json.dumps(
      {
        "samples": len(descriptions),
        "max_features": args.max_features,
        "ngram_max": args.ngram_max,
      },
      indent=2,
    ),
    encoding="utf-8",
  )
  print(f"Artifacts saved to {output_dir}")


if __name__ == "__main__":
  main()

