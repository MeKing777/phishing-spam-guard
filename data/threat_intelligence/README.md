# Threat-classification datasets

This folder is generated locally by `python -m tools.build_threat_dataset`.
It contains separate `train.jsonl` and `test.jsonl` files with synthetic
examples labelled `benign`, `spam`, `phishing`, or `harmful_url`. The benign
email holdout includes a labeled AWS course-badge message from Credly, with a
sender display name, so this ordinary message type is distinct from prize and
giveaway spam.
All records
are marked `source: synthetic` and `is_synthetic: true`; `.test` and `.invalid`
domains are reserved examples, not live threat indicators.

These JSONL files are synthetic pipeline fixtures, not production training
data or a real-world threat-intelligence feed. Synthetic examples are
deliberately simple and must not be used to decide whether real users' mail or
URLs are safe. The Atlas loader uses the larger pinned public corpora described
below instead of uploading these fixtures.

## Load into MongoDB Atlas

1. Create a Free cluster and database user in Atlas. Add your current public
   IP address to the project's network access list.
2. Install the data and database dependencies: `pip install -r requirements-atlas.txt`.
3. Set `MONGODB_URI` locally to the Atlas `mongodb+srv://...` connection
   string. Do not put the URI in source control, the browser extension, or
   chat. The database user should have write access only to the target database.
4. Run `python -m tools.load_atlas_dataset`.

After you run the loader, it idempotently upserts the pinned public corpora
into `alerter_training` by default. Set `ALERTER_MONGODB_DATABASE` to use
another database name. Email labels are `benign`, `spam`, and `phishing`; URL
labels are `legitimate` and `phishing`. Separate collections hold the grouped
train, validation, and test splits for each kind, and `dataset_catalog`
records source citations, licenses, counts, and limitations. The loader uses
only public corpora; it does not read or upload inbox contents, messages, or
browsing history. Atlas remains a data store; loading records does not train
or power live scans.

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
