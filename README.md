# warc-metadata-sidecar

This library will consume a warc file, read each record and create a new record with metadata that will be stored in the sidecar 'warc.meta.gz' file.

## Requirements

- Python 3.6

## Installation

It is recommended to work in a virtual environment.

At the root folder of warc-metadata-sidecar, install:

    $ python setup.py install

For usage instructions run:

    $ warc_metadata_sidecar.py --help

Example:

    $ warc_metadata_sidecar.py warc_filename.warc.gz example_dirname

### License

See LICENSE.

### Contributors

- [Gracie Flores-Hays](https://github.com/gracieflores)