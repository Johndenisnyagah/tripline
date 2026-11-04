# tests/corpora/

`manifest.yml` lists background corpora (URL, sha256, licence, label). They are downloaded
in CI into `cache/` and never committed. Hit counts are reported as hits on an unlabelled
corpus, not as a false-positive rate.
