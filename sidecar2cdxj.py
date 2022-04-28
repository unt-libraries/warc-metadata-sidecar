import argparse
import ast
import json
import os
import re

import surt
from warcio.archiveiterator import ArchiveIterator
from warcio.timeutils import iso_date_to_timestamp


def create_sidecar_cdxj(sidecar_file, archive_dir):
    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)

    warc_file = os.path.basename(sidecar_file)
    cdxj_file = re.sub('warc.meta.gz', 'cdxj', warc_file)
    sidecar_file_path = os.path.join(archive_dir, cdxj_file)

    with open(sidecar_file_path, 'wt') as out, open(sidecar_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'warcinfo':
                continue
            string_payload = record.content_stream().read().decode("utf-8")
            payload_list = string_payload.split('\n')
            new_dict = {}
            for item in payload_list:
                item_list = item.split(': ', 1)
                try:
                    item_value = ast.literal_eval(item_list[1])
                    new_dict[item_list[0]] = item_value
                except ValueError:
                    new_dict[item_list[0]] = item_list[1]
            surt_url = surt.surt(record.rec_headers.get_header('WARC-Target-URI'))
            ts = iso_date_to_timestamp(record.rec_headers.get_header('WARC-Date'))
            out.write(surt_url + " " + ts + " " + json.dumps(new_dict) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'sidecar_file',
        action='store',
        help='A WARC metadata sidecar file that will be used to generate a cdxj.'
    )
    parser.add_argument(
        'archive_dir',
        action='store',
        help='A directory where the cdxj file will be stored.'
    )
    args = parser.parse_args()
    create_sidecar_cdxj(args.sidecar_file, args.archive_dir)


if __name__ == '__main__':
    main()
