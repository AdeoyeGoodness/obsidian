# Training the Threat Models

The runtime service simply loads the pickled artifacts inside `models copy/`. This
folder contains a lightweight training utility that produces those pickles from a
CSV dataset.

## Dataset format

Provide a UTF-8 CSV with the following columns:

| column        | description                                        |
| ------------- | -------------------------------------------------- |
| `description` | Raw CVE description text                           |
| `cwe`         | Comma/semicolon-separated CWE identifiers          |
| `capec`       | Comma/semicolon-separated CAPEC identifiers        |

Example row:

```
description,cwe,capec
"Improper neutralization of input in parser…","CWE-89;CWE-20","CAPEC-66"
```

## Running the trainer

```bash
cd services/threat-model
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python training/train.py \
  --dataset path/to/cves.csv \
  --output ./artifacts \
  --max-features 25000 \
  --ngram-max 2
```

The script writes the five pickled artifacts plus `metadata.json` into the output
directory. Copy those files into `models copy/` (or wherever `THREAT_MODELS_PATH`
points) before restarting the FastAPI service.

## Notes

- Increase `--max-features` or `--ngram-max` for richer vocabularies at the cost
  of memory/CPU.
- Use `--jobs` to parallelise `OneVsRestClassifier`.
- Keep the training scikit-learn version aligned with the runtime (currently 1.5.x)
  to avoid pickle incompatibility warnings.

