
.. _zip-module:

##########
zip module
##########

.. versionadded:: 4.7.0

The zip module exposes metadata parsed from the ZIP central directory. It can
be used to triage archives by entry count, declared size, compression ratio,
encryption, path traversal, and nested ZIP depth.

ZIP64 central directories and entries written with data descriptors are
supported. The central directory is authoritative, so sizes remain available
for entries whose local headers use data descriptors.

The module must be enabled at build time with ``--enable-zip``. It depends on
zlib.

.. code-block:: yara

    import "zip"

    rule suspicious_nested_zip_bomb
    {
        condition:
            zip.valid and
            zip.max_ratio > 100.0 and
            zip.nested_depth >= 1
    }

Reference
---------

.. c:type:: valid

    Set to 1 when a complete ZIP end-of-central-directory record and its central
    directory were parsed successfully. Corrupt or truncated archives report 0.

    *Example: zip.valid*

.. c:type:: entries

    Number of entries in the central directory.

    *Example: zip.entries > 1000*

.. c:type:: uncompressed_size

    Sum of the uncompressed sizes declared by all central directory entries.

    *Example: zip.uncompressed_size > 500000000*

.. c:type:: compressed_size

    Sum of the compressed sizes declared by all central directory entries.

    *Example: zip.compressed_size < 100000*

.. c:type:: max_ratio

    Maximum uncompressed-to-compressed size ratio across all entries, returned
    as a floating point number. An entry with a zero compressed size and a non-
    zero uncompressed size uses its uncompressed size as the ratio.

    *Example: zip.max_ratio > 100.0*

.. c:type:: is_encrypted

    Set to 1 when at least one central directory entry has the encryption flag
    set.

    *Example: zip.is_encrypted*

.. c:type:: has_traversal

    Set to 1 when an entry name is absolute or contains a ``..`` path component.
    Both ``/`` and ``\`` are treated as path separators.

    *Example: zip.has_traversal*

.. c:type:: nested_depth

    Maximum depth of ZIP archives found inside entries. A top-level archive with
    no nested ZIP has depth 0, an archive containing one nested ZIP has depth 1,
    and so on. Stored and deflate-compressed entries are inspected within a
    bounded decompression budget.

    *Example: zip.nested_depth >= 2*

.. c:function:: entry_name(index)

    Returns the name of the entry at the zero-based *index*. Returns an
    undefined value when the index is out of range.

    *Example: zip.entry_name(0) == "setup.exe"*
