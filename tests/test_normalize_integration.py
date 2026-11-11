import pytest

from spider.engine.scan import scan_directory


def test_normalization_marks_findings_and_preserves_original_file(monkeypatch, tmp_path):
    source = "import os\nos.system('id')\n"
    target = tmp_path / "sample.py"
    target.write_text(source, encoding="utf-8")
    original_bytes = target.read_bytes()

    monkeypatch.setattr(
        "spider.engine.scan.normalize_source",
        lambda code: code + "\n# normalized in memory\n",
    )

    record = scan_directory(tmp_path, normalize=True)

    assert target.read_bytes() == original_bytes
    assert record["findings"]
    assert all(
        finding["context"]["after_normalization"] is True
        for finding in record["findings"]
    )


def test_normalization_disabled_by_default(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nos.system('id')\n", encoding="utf-8")

    record = scan_directory(tmp_path)

    assert record["findings"]
    assert all(
        finding["context"]["after_normalization"] is False
        for finding in record["findings"]
    )


def test_normalization_failure_falls_back_to_original(monkeypatch, tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("import os\nos.system('id')\n", encoding="utf-8")

    def fail_normalization(_source):
        raise ValueError("test normalization failure")

    monkeypatch.setattr(
        "spider.engine.scan.normalize_source",
        fail_normalization,
    )

    with pytest.warns(RuntimeWarning, match="Normalization failed"):
        record = scan_directory(tmp_path, normalize=True)

    assert record["findings"]
    assert all(
        finding["context"]["after_normalization"] is False
        for finding in record["findings"]
    )
