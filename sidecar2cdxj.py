import argparse
import io
import json
import os
import re

import surt
from warcio.archiveiterator import ArchiveIterator
from warcio.timeutils import iso_date_to_timestamp


def create_cdxj(sidecar_file, archive_dir):
    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)

    warc_file = os.path.basename(sidecar_file)
    cdxj_file = re.sub('warc.meta.gz', 'cdxj', warc_file)
    sidecar_file_path = os.path.join(archive_dir, cdxj_file)

    with open(sidecar_file_path, 'wt') as out, open(sidecar_file, 'rb') as stream:
        for record in ArchiveIterator(stream):
            if record.rec_type == 'warcinfo':
                continue
            payload = io.BytesIO(record.content_stream().read())
            payload.seek(0)
            string_payload = payload.read().decode("utf-8")
            payload_list = string_payload.split('\n')
            new_dict = {}
            for item in payload_list:
                new_item = item.split(': ', 1)
                new_dict[new_item[0]] = new_item[1]
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
    create_cdxj(args.sidecar_file, args.archive_dir)


if __name__ == '__main__':
    main()
