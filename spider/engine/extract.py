"""Safe archive extraction (stdlib only). Treats every archive as hostile data.

safe_extract(archive, dest, ...) -> dict
    {"files": int, "bytes": int, "rejected": [{"name", "reason"}], "limits_hit": [str]}

Policy
- Only regular files and directories are written. Symlinks, hardlinks, devices, fifos are rejected.
- Rejected names: absolute paths, "..", NUL bytes, Windows drive letters, Windows reserved device
  names (con, aux, nul, com1..), paths longer than max_path.
- Written files get default permissions (no exec bit is ever set).
- Limits: max_files, max_total_bytes, max_member_bytes, expansion ratio (uncompressed : archive size).
  Hitting a global limit stops extraction and is reported in limits_hit (caller => unable_to_assess).
- Sizes are counted from the bytes actually read, never trusted from headers.
Supported: .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz, .zip, .whl
"""
import os
import re
import tarfile
import zipfile

WIN_RESERVED = {"con", "prn", "aux", "nul"} | {"com%d" % i for i in range(1, 10)} | {"lpt%d" % i for i in range(1, 10)}
CHUNK = 64 * 1024


def bad_name(name, max_path=240):
    if "\x00" in name:
        return "nul_byte"
    n = name.replace("\\", "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return "absolute_path"
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if ".." in parts:
        return "path_traversal"
    if len(n) > max_path:
        return "path_too_long"
    for p in parts:
        if p.split(".")[0].lower() in WIN_RESERVED:
            return "windows_reserved_name"
    return None


class _State:
    def __init__(self, dest, max_files, max_total_bytes, max_member_bytes, max_ratio, archive_size, max_path):
        self.dest = os.path.realpath(dest)
        self.max_files, self.max_total = max_files, max_total_bytes
        self.max_member, self.max_ratio = max_member_bytes, max_ratio
        self.archive_size = max(1, archive_size)
        self.max_path = max_path
        self.files = 0
        self.bytes = 0
        self.rejected = []
        self.limits_hit = []
        self.stop = False

    def reject(self, name, reason):
        self.rejected.append({"name": name[:200], "reason": reason})

    def target(self, name):
        reason = bad_name(name, self.max_path)
        if reason:
            self.reject(name, reason)
            return None
        parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
        path = os.path.realpath(os.path.join(self.dest, *parts))
        if path != self.dest and not path.startswith(self.dest + os.sep):
            self.reject(name, "path_traversal")
            return None
        return path

    def hit(self, limit):
        if limit not in self.limits_hit:
            self.limits_hit.append(limit)
        self.stop = True

    def write(self, name, path, reader):
        if self.files >= self.max_files:
            self.hit("max_files")
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        written = 0
        too_big = False
        with open(path, "wb") as out:
            while True:
                chunk = reader.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > self.max_member:
                    too_big = True
                    break
                if self.bytes + written > self.max_total:
                    out.close()
                    os.remove(path)
                    self.hit("max_total_bytes")
                    return
                out.write(chunk)
        if too_big:
            os.remove(path)
            self.reject(name, "too_large")
            return
        self.files += 1
        self.bytes += written
        if self.bytes > 10 * 1024 * 1024 and self.bytes / self.archive_size > self.max_ratio:
            self.hit("expansion_ratio")


def safe_extract(archive, dest, *, max_files=20000, max_total_bytes=100 * 1024 * 1024,
                 max_member_bytes=2 * 1024 * 1024, max_ratio=100, max_path=240):
    archive = str(archive)
    os.makedirs(dest, exist_ok=True)
    st = _State(dest, max_files, max_total_bytes, max_member_bytes, max_ratio, os.path.getsize(archive), max_path)
    if zipfile.is_zipfile(archive):
        _zip(archive, st)
    else:
        try:
            _tar(archive, st)
        except tarfile.TarError as exc:
            st.reject(os.path.basename(archive), "unreadable_archive:%s" % type(exc).__name__)
    return {"files": st.files, "bytes": st.bytes, "rejected": st.rejected, "limits_hit": st.limits_hit}


def _tar(archive, st):
    with tarfile.open(archive, "r:*") as tf:
        for m in tf:
            if st.stop:
                break
            if m.isdir():
                p = st.target(m.name)
                if p:
                    os.makedirs(p, exist_ok=True)
                continue
            if not m.isreg():
                kind = "symlink" if m.issym() else "hardlink" if m.islnk() else "special_file"
                st.reject(m.name, kind)
                continue
            p = st.target(m.name)
            if not p:
                continue
            f = tf.extractfile(m)
            if f is None:
                st.reject(m.name, "unreadable_member")
                continue
            st.write(m.name, p, f)


def _zip(archive, st):
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if st.stop:
                break
            mode = (info.external_attr >> 16) & 0o170000
            if info.is_dir():
                p = st.target(info.filename)
                if p:
                    os.makedirs(p, exist_ok=True)
                continue
            if mode == 0o120000:
                st.reject(info.filename, "symlink")
                continue
            if mode not in (0, 0o100000):
                st.reject(info.filename, "special_file")
                continue
            if info.file_size > 1024 * 1024 and info.file_size / max(1, info.compress_size) > st.max_ratio:
                st.reject(info.filename, "expansion_ratio")
                continue
            p = st.target(info.filename)
            if not p:
                continue
            with zf.open(info) as f:
                st.write(info.filename, p, f)
