import argparse
import json
import os
import re

import surt
from warcio.archiveiterator import ArchiveIterator
from warcio.timeutils import iso_date_to_timestamp


def create_cdxj_path(sidecar_file, archive_dir):
    """Take the sidecar file, replace the extension, and return the path/filename of the CDXJ."""
    warc_file = os.path.basename(sidecar_file)
    cdxj_file = re.sub('warc.meta.gz', 'cdxj', warc_file)
    return os.path.join(archive_dir, cdxj_file)


def convert_payload_to_json(record):
    """Parse a record's payload, put the fields into a dictionary and return the dictionary."""
    string_payload = record.content_stream().read().decode('utf-8')
    payload_list = string_payload.split('\n')
    new_dict = {}
    for item in payload_list:
        item_key, value = item.split(': ', 1)
        new_dict[item_key] = json.loads(value)
    return json.dumps(new_dict)


def record_data_to_string(record):
    """Convert dictionary into JSON object, convert record fields and JSON into a string."""
    json_string = convert_payload_to_json(record)
    surt_url = surt.surt(record.rec_headers.get_header('WARC-Target-URI'))
    ts = iso_date_to_timestamp(record.rec_headers.get_header('WARC-Date'))
    return surt_url + ' ' + ts + ' ' + json_string + '\n'


def create_sidecar_cdxj(sidecar_file, archive_dir):
    """Create a CDXJ index from a WARC formatted metadata sidecar file.

    Iterate the metadata records of a WARC metadata sidecar file,
    and write a line to a CDXJ file containing the SURT-formatted URI,
    timestamp, and JSON data block representing the record's payload
    key value pairs.
    Keyword arguments:
    sidecar_file -- path to sidecar metadata WARC
    archive_dir -- path to output directory for the CDXJ
    """
    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)

    cdxj_path = create_cdxj_path(sidecar_file, archive_dir)

    with open(cdxj_path, 'wt') as out, open(sidecar_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'warcinfo':
                continue
            record_string = record_data_to_string(record)
            out.write(record_string)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'sidecar_file',
        action='store',
        help='A WARC metadata sidecar file that will be used to generate a CDXJ.'
    )
    parser.add_argument(
        'archive_dir',
        action='store',
        help='A directory where the CDXJ file will be stored.'
    )
    args = parser.parse_args()
    create_sidecar_cdxj(args.sidecar_file, args.archive_dir)


if __name__ == '__main__':
    main()
