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
    codes = []
    for lang_dict in lang_list:
        lang_code = lang_dict['code']
        try:
            new_code = Language.get(lang_code).to_alpha3()
        except LookupError as err:
            new_code = ''
            logging.error(err)
        # We only want to include the language if it has a 3 letter code.
        if len(new_code) == 3:
            codes.append(new_code)
    # The codes need to be comma separated values.
    lang_codes = ','.join(codes)
    return lang_codes


def get_sidecar_fields(original_obj, meta_obj):
    """Collect the sidecar fields and add them to the original WARC dict.
    
    Sidecar fields to collect: mime, puid, charset, languages, and soft404
    """
    if meta_obj.get('Identified-Payload-Type'):
        # Choosing python-magic over fido, due to broader choices.
        if meta_obj['Identified-Payload-Type'].get('python-magic'):
            mime = meta_obj['Identified-Payload-Type']['python-magic']
        else:
            mime = meta_obj['Identified-Payload-Type']['fido']
        original_obj['mime-detected'] = mime
    if meta_obj.get('Preservation-Identifier'):
        puid = meta_obj['Preservation-Identifier']
        original_obj['puid'] = puid
    if meta_obj.get('Charset-Detected'):
        charset = meta_obj['Charset-Detected']['encoding']
        original_obj['charset'] = charset
    if meta_obj.get('Languages-cld2'):
        lang_array = meta_obj['Languages-cld2']['languages']
        new_codes = get_alpha3_language_codes(lang_array)
        if new_codes:
            original_obj['languages'] = new_codes
    if meta_obj.get('Soft-404-Detected'):
        soft404 = meta_obj['Soft-404-Detected']
        original_obj['soft-404-detected'] = soft404
    return original_obj


def merge_meta_fields(meta_dict, original_cdxj):
    """Find the matching keys, merge the JSON objects, then update the line for the new CDXJ."""
    edited_count = 0
    non_edited_count = 0
    list_of_merged = []
    # There could be times that the original cdxj has more than one of the same 'key'.
    # We will match each line by looping.
    for line in original_cdxj:
        urlkey, timestamp, cdxj_obj = line.split(' ', 2)
        # Set the key for matching.
        urlkey_and_timestamp = urlkey + ' ' + timestamp
        # If the original key is a match with a meta cdxj key, then merge the field objects.
        # This includes merging fields to any duplicate keys from original cdxj.
        if meta_dict.get(urlkey_and_timestamp):
            edited_count += 1
            meta_obj = meta_dict[urlkey_and_timestamp]
            original_obj = json.loads(cdxj_obj)
            updated_obj = get_sidecar_fields(original_obj, meta_obj)
            list_of_merged.append(urlkey_and_timestamp + ' ' + json.dumps(updated_obj) + '\n')
        # If it does not match, we still want the original.
        else:
            non_edited_count += 1
            list_of_merged.append(line)
    return (list_of_merged, edited_count, non_edited_count)


def create_dict_from_meta(meta_cdxj):
    """Convert the URL/timestamp and JSON object into a dictionary for easy look up."""
    meta_dict = {}
    for line in meta_cdxj:
        m_key, timestamp, meta_obj = line.split(' ', 2)
        key_and_timestamp = m_key + ' ' + timestamp
        json_obj = json.loads(meta_obj)
        meta_dict[key_and_timestamp] = json_obj
    return meta_dict


def create_cdxj_path(warc_cdxj, cdxj_dir):
    """Take the WARC CDXJ, replace the extension, and return the path/filename of the CDXJ."""
    w_cdxj = os.path.basename(warc_cdxj)
    cdxj_file = re.sub(r'\.cdxj$', '_merged.cdxj', w_cdxj)
    logging.info('Creating CDXJ %s', cdxj_file)
    return os.path.join(cdxj_dir, cdxj_file)


def merge_cdxjs(metadata_cdxj, warc_cdxj, cdxj_dir):
    """Merge fields from a sidecar CDXJ with an original WARC CDXJ.

    Finding the matching key (SURT URL and timestamp) of the CDXJ's,
    collect the wanted fields from the sidecar CDXJ, combine them
    with the original WARC CDXJ and write the combined records to a
    new CDXJ file.
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

    cdxj_path = create_cdxj_path(warc_cdxj, cdxj_dir)

    with open(cdxj_path, 'wt') as merged_cdxj, open(metadata_cdxj, 'r') as meta_cdxj, \
         open(warc_cdxj, 'r') as original_cdxj:

        meta_dict = create_dict_from_meta(meta_cdxj)
        list_of_original, edited, non_edited = merge_meta_fields(meta_dict, original_cdxj)
        for line in list_of_original:
            merged_cdxj.write(line)

        logging.info('Finished merging in %s',
                     str(timedelta(seconds=(time.time() - start))))
        print('Merged {} + {} => {}\tTotal merged records: {}'.format(warc_cdxj, metadata_cdxj,
                                                                      cdxj_path, edited))
        logging.info('Total merged records: %s', edited)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-m',
        '--metadata_cdxj',
        action='store',
        required=True,
        help='A CDXJ file created from a metadata sidecar WARC file.'
    )
    parser.add_argument(
        '-w',
        '--warc_cdxj',
        action='store',
        required=True,
        help='A CDXJ file with data from a WARC file.'
    )
    parser.add_argument(
        '-d',
        '--cdxj_dir',
        action='store',
        required=True,
        help='A directory where the merged CDXJ file will be stored.'
    )
    args = parser.parse_args()
    merge_cdxjs(args.metadata_cdxj, args.warc_cdxj, args.cdxj_dir)


if __name__ == '__main__':
    main()
