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
