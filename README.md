Case Sensitive FS
=================

Turn `HFS` like case in-sensitive fs into case sensitive fs.

Need more debug info?
```bash
LD_DEBUG=symbols ls a.py
```

Usage
-----

```bash
make build
export LD_PRELOAD=$PWD/case_sensitive_fs.so
export LD_CASE_SENSITIVE_AUTOFIX_BASES=/test:/test2
```
