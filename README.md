# warc-metadata-sidecar

[![Build Status](https://github.com/unt-libraries/warc-metadata-sidecar/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/unt-libraries/warc-metadata-sidecar/actions)

This library is intended to extract data into a metadata sidecar from WARC/ARC files, convert the
sidecar data into a CDXJ file, and then merge that CDXJ with a CDXJ created from the original WARC.

## Installation

It is recommended to work in a virtual environment.

At the root folder of warc-metadata-sidecar, install:

    $ pip install -e .

## warc_metadata_sidecar.py

This script will consume a WARC or ARC file, read each record that is a response or resource type,
and create a new record with metadata that will be stored in a sidecar file. The sidecar records
will include the mimetype and puid, character set, and language if found. The character set and
language will only be searched for 'text' formats. The extension 'meta' will be added to the
sidecar file
(i.e. filename.warc.gz becomes filename.warc.meta.gz and file.arc.gz becomes file.warc.meta.gz).

For usage instructions run:

    $ warc_metadata_sidecar.py --help

Example:

    $ warc_metadata_sidecar.py example_dirname warc_filename.warc.gz

    $ warc_metadata_sidecar.py dir_name file.warc.gz --operator 'Operator Name' --publisher 'Name'

## sidecar2cdxj.py

This script will take the URI, timestamp, and fields from the payload of each metadata record in a
sidecar file and write the data into a file using the CDXJ format.

For usage instructions run:

    $ sidecar2cdxj.py --help

Example:

    $ sidecar2cdxj.py sidecar_filename.warc.meta.gz directory_name

## merge_cdxj.py

This script will take a CDXJ from an original WARC and a metadata sidecar CDXJ, find the matching URI and
timestamp from each file, collect certain fields from the metadata sidecar CDXJ (mime type, puid,
charset, language, and soft-404), merge those fields with the original CDXJ data, and put the
merged data into a new CDXJ.

For usage instructions run:

    $ merge_cdxj.py --help

Example:

    $ merge_cdxj.py sidecar.cdxj original.cdxj directory_name

## Testing

    $ pip install pytest

Run:

    $ pytest

### License

See LICENSE.

### Contributors

- [Gracie Flores-Hays](https://github.com/gracieflores)