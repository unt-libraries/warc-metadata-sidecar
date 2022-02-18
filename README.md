# warc-metadata-sidecar

[![Build Status](https://github.com/unt-libraries/warc-metadata-sidecar/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/unt-libraries/warc-metadata-sidecar/actions)

This library will consume a WARC file, read each record that is a response or resource type, and
create a new record with metadata that will be stored in a sidecar file. The sidecar records will
include the mimetype and puid, character set, and language if found. The character set and language
will only be searched for 'text' formats. The extension 'meta' will be added to the sidecar file
(i.e. filename.warc.gz becomes filename.warc.meta.gz).

## Installation

It is recommended to work in a virtual environment.

At the root folder of warc-metadata-sidecar, install:

    $ pip install -e .

For usage instructions run:

    $ warc_metadata_sidecar.py --help

## Example Usage:

    $ warc_metadata_sidecar.py warc_filename.warc.gz example_dirname

    $ warc_metadata_sidecar.py file.warc.gz dir_name --operator 'Operator Name' --publisher 'Name'

## Testing

    $ pip install pytest

Run:

    $ pytest

### License

See LICENSE.

### Contributors

- [Gracie Flores-Hays](https://github.com/gracieflores)