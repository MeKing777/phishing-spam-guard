# Synthetic threat-classification seed data

This folder is generated locally by `python -m tools.build_threat_dataset`.
It contains separate `train.jsonl` and `test.jsonl` files with synthetic
examples labelled `benign`, `spam`, `phishing`, or `harmful_url`. All records
are marked `source: synthetic` and `is_synthetic: true`; `.test` and `.invalid`
domains are reserved examples, not live threat indicators.

**This is plumbing/demo data, not a trained or validated detector and not a
real-world threat-intelligence feed.** Synthetic examples are deliberately
simple and must not be used to decide whether real users' mail or URLs are
safe. To build a useful classifier, replace or augment this seed with
lawfully obtained, representative, independently labelled data; split by
campaign/domain/source to avoid train/test leakage; and measure per-class
precision, recall, false-positive rates, and calibration before deployment.

## Load into MongoDB Atlas

1. Create a Free cluster and database user in Atlas. Add your current public
   IP address to the project's network access list.
2. Install the optional driver: `pip install -r requirements-atlas.txt`.
3. Set `MONGODB_URI` locally to the Atlas `mongodb+srv://...` connection
   string. Do not put the URI in source control, the browser extension, or
   chat. The database user should have write access only to the target database.
4. Run `python -m tools.load_atlas_dataset`.

The loader idempotently upserts only the generated synthetic records into
`alerter_training.train_samples` and `alerter_training.test_samples` by
default. Set `ALERTER_MONGODB_DATABASE` to use another database name. It
does not read or upload inbox contents, messages, or browsing history. Atlas
is a data store; loading examples alone does not train the current Alerter
heuristics or add a threat feed to live scans.

## Local supervised models

`python -m tools.train_local_models` downloads fixed revisions of public corpora
to the ignored `data/training_sources/` directory and writes local model files
to the ignored `models/` directory. It does not use Atlas or read mailbox data.
The email trainer combines the CC0 spam/ham mirror and the LGPL-3.0 phishing
email dataset. The URL trainer uses the CC BY 4.0 Hannousse–Yahiouche phishing
URL benchmark. Attribution, revision-pinned source links, class counts, split
method, conservative warning thresholds, and held-out metrics are recorded in
`training_report.json`. Warnings target at least 98% validation precision when
that threshold can be achieved.

The datasets are historical and may have source overlap or labeling bias.
Exact normalized email duplicates and URL hostnames are group-separated across
train, validation, and test partitions, but semantic near-duplicates and
registrable-domain variants may remain. Do not interpret the resulting metrics
as proof of protection against current threats.
