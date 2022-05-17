import argparse
import json
import logging
import os
import re
import time
from datetime import timedelta

from langcodes import Language


def get_alpha3_language_codes(lang_list):
    """Find each language code and convert it to alpha3 using langcodes."""
    code = []
    new_code = ''
    for dict in lang_list:
        lang_code = dict['code']
        try:
            new_code = Language.get(lang_code).to_alpha3()
        except LookupError as err:
            print(err)
            logging.error(err)
        # We only want to include the language if it has a 3 letter code.
        if len(new_code) == 3:
            code.append(new_code)
    # The codes need to be comma separated values.
    lang_codes = ','.join(code)
    return lang_codes


def get_sidecar_fields(original_obj, detail):
    """Collect the mime, charset, languages, and soft404 to add them to the original WARC dict."""
    if detail.get('Identified-Payload-Type'):
        # Choosing python-magic over fido, due to broader choices
        if detail['Identified-Payload-Type'].get('python-magic'):
            mime = detail['Identified-Payload-Type']['python-magic']
        else:
            mime = detail['Identified-Payload-Type']['fido']
        original_obj['mime-detected'] = mime
    if detail.get('Charset-Detected'):
        charset = detail['Charset-Detected']['encoding']
        original_obj['charset'] = charset
    if detail.get('Languages-cld2'):
        lang_array = detail['Languages-cld2']['languages']
        new_codes = get_alpha3_language_codes(lang_array)
        if new_codes:
            original_obj['languages'] = new_codes
    if detail.get('Soft-404-Detected'):
        soft404 = detail['Soft-404-Detected']
        original_obj['soft-404-detected'] = soft404
    return original_obj


def merge_meta_fields(original_dict, duplicate_dict, meta_cdxj):
    """Combine fields from the sidecar CDXJ to the matching url/timestamp of the dictionaries."""
    matched_count = 0
    for meta in meta_cdxj:
        meta_urlkey, meta_timestamp, meta_obj = meta.split(' ', 2)
        meta_urlkey_and_timestamp = meta_urlkey + ' ' + meta_timestamp
        if original_dict.get(meta_urlkey_and_timestamp):
            original_obj = original_dict[meta_urlkey_and_timestamp]
            matched_count += 1
            detail = json.loads(meta_obj)
            updated_obj = get_sidecar_fields(original_obj, detail)
            original_dict[meta_urlkey_and_timestamp] = updated_obj
            # print(original_dict[meta_urlkey_and_timestamp])
            if duplicate_dict.get(meta_urlkey_and_timestamp):
                duplicate_obj = duplicate_dict[meta_urlkey_and_timestamp]
                updated_duplicate_obj = get_sidecar_fields(duplicate_obj, detail)
                duplicate_dict[meta_urlkey_and_timestamp] = updated_duplicate_obj
    return (original_dict, duplicate_dict, matched_count)


def create_dict_from_original(original_cdxj):
    """Convert the JSON object into a dictionary for easy look up."""
    original_count = 0
    original_dict = {}
    duplicate_dict = {}
    # print(original_cdxj)
    for line in original_cdxj:
        # print(line)
        original_count += 1
        urlkey, timestamp, main_obj = line.split(' ', 2)
        # Combine the surt URL and timestamp to use as the 'key'.
        urlkey_and_timestamp = urlkey + ' ' + timestamp
        # print(main_obj)
        json_obj = json.loads(main_obj)
        if not original_dict.get(urlkey_and_timestamp):
            original_dict[urlkey_and_timestamp] = json_obj
        # if key already exists... do something else? make another dictionary? ignore the rest?
        else:
            # print(original_dict[urlkey_and_timestamp])
            print('We have a duplicate')
            print(urlkey_and_timestamp)
            duplicate_dict[urlkey_and_timestamp] = json_obj
    return (original_dict, duplicate_dict, original_count)


def merge_cdxjs(metadata_cdxj, warc_cdxj, cdxj_dir):
    """Merge fields from a sidecar cdxj into an original warc cdxj.

    Finding the matching key (surt URL and timestamp) of the CDXJ's,
    collect the wanted fields from the sidecar CDXJ and combine them
    into the original warc CDXJ.
    """
    start = time.time()
    if not os.path.isdir(cdxj_dir):
        os.mkdir(cdxj_dir)

    logging.basicConfig(
        filename=os.path.join(cdxj_dir, 'cdxj_merge.log'),
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
    )
    logging.getLogger(__name__)
    logging.info('Logging CDXJ merge information for %s and %s', warc_cdxj, metadata_cdxj)

    w_cdxj = os.path.basename(warc_cdxj)
    # Not sure what to do here, what shall we name the merged file... merge_sidecar_cdxj?
    cdxj_file = re.sub(r'\.cdxj$', '_merged.cdxj', w_cdxj)
    logging.info('Creating CDXJ %s', cdxj_file)
    cdxj_path = os.path.join(cdxj_dir, cdxj_file)

    with open(cdxj_path, 'wt') as merged_cdxj, open(metadata_cdxj, 'r') as meta_cdxj, \
         open(warc_cdxj, 'r') as original_cdxj:

        original_dict, duplicate_dict, original_count = create_dict_from_original(original_cdxj)
        updated_dict, updated_duplicate, matched_count = merge_meta_fields(original_dict,
                                                                           duplicate_dict,
                                                                           meta_cdxj)

        for key, value in updated_dict.items():
            merged_cdxj.write(key + ' ' + json.dumps(value) + '\n')
        for key, value in updated_duplicate.items():
            merged_cdxj.write(key + ' ' + json.dumps(value) + '\n')

        logging.info('Finished creating sidecar in %s',
                     str(timedelta(seconds=(time.time() - start))))
        print('Total matched records:', matched_count)
        logging.info('Total matched records: %s', matched_count)
        print('Total count from', w_cdxj + ':', original_count)  # maybe this is unecessary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'metadata_cdxj',
        action='store',
        help='A CDXJ file created from a metadata sidecar WARC file.'
    )
    parser.add_argument(
        'warc_cdxj',
        action='store',
        help='A CDXJ file with data from a WARC file.'
    )
    parser.add_argument(
        'cdxj_dir',
        action='store',
        help='A directory where the merged CDXJ file will be stored.'
    )
    args = parser.parse_args()
    merge_cdxjs(args.metadata_cdxj, args.warc_cdxj, args.cdxj_dir)


if __name__ == '__main__':
    main()
