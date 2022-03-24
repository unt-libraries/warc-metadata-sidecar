#!/usr/bin/python
import argparse
import io
import logging
import os
import pkg_resources
import re
import regex
import socket
import time
from datetime import timedelta

import chardet
import magic
import pycld2 as cld2
from fido.fido import Fido
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter


MIME_TITLE = 'Identified-Payload-Type:'
PUID_TITLE = 'Preservation-Identifier:'
CHARSET_TITLE = 'Charset-Detected:'
LANGUAGE_TITLE = 'Languages-cld2:'

BAD_CHARS = regex.compile(r'\p{Cc}|\p{Cs}|\p{Cn}')

TEXT_FORMAT_MIMES = re.compile(r'(text|html|xml)')  # this may change


class ExtendFido(Fido):
    """A class that extends Fido to override some methods."""
    def blocking_read(self, file, bytes_to_read):
        """Read all bytes into buffer and return.

        Remedies a known issue of the method hanging when identify_stream is called.
        Modifies the if statement to break out when the end of the stream is reached.
        https://github.com/openpreserve/fido/blob/093cf9c8c968c710d3d6dfbbcc6e067cd9e27ef3/fido/fido.py#L518
        """
        bytes_read = 0
        buffer = b''
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            buffer += readbuffer
            bytes_read = len(buffer)
            if not readbuffer:
                break
        return buffer

    def identify_stream(self, stream):
        """Override identify_stream to get the matches, mime type, and puid"""
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream)
        self.current_filesize = bytes_read
        matches = self.match_formats(bofbuffer, eofbuffer)
        puid = None
        fido_mime = None
        if matches:
            match_format, _ = matches[0]
            mime = match_format.find('mime')
            fido_mime = mime.text if mime is not None else None
            puid = self.get_puid(match_format)
        return (fido_mime, puid)


def find_mime_and_puid(fido, payload):
    """Find the mimetype and preservation identifier using fido and python-magic."""
    # Using fido to find mimetype and puid.
    fido_mime, puid = fido.identify_stream(payload)
    # Using python-magic to find mimetype.
    payload.seek(0)
    magic_mime = magic.from_buffer(payload.read(), mime=True)
    mime_dict = {}
    if fido_mime:
        mime_dict['fido'] = fido_mime
    if magic_mime:
        mime_dict['python-magic'] = magic_mime
    return (mime_dict, puid)


def find_character_set(bytes_payload):
    """Find the character set of the payload using chardet."""
    result = chardet.detect(bytes_payload)
    result_dict = {'encoding': result['encoding'],
                   'confidence': result['confidence']
                   }
    return result_dict


def find_language(bytes_load):
    """Find the language of the payload using pycld2."""
    is_reliable, bytes_found, details = cld2.detect(BAD_CHARS.sub('',
                                                                  bytes_load.decode('utf-8',
                                                                                    'replace')),
                                                    bestEffort=True)
    new_list = []
    # 'details' seems to always return 3, if the language is 'Unknown' we don't need to list it.
    for item in details:
        if item[0] != 'Unknown':
            new_list.append({
                'name': item[0],
                'code': item[1],
                'text-covered': item[2],
                'score': item[3]})
    if new_list:
        lang_cld = {'reliable': is_reliable,
                    'text-bytes': bytes_found,
                    'languages': new_list}
        return lang_cld
    else:
        return None


def create_warcinfo_payload(new_file, operator=None, publisher=None):
    """Collect WARC fields to create warcinfo record payload."""
    hostname = socket.gethostname()
    version = pkg_resources.require('warc-metadata-sidecar')[0].version
    warc_doc = 'http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf'
    warcinfo_payload = {'software': 'warc-metadata-sidecar/' + version,
                        'hostname': hostname,
                        'ip': socket.gethostbyname(hostname),
                        'conformsTo': warc_doc,
                        'description': 'WARC metdata sidecar for ' + new_file}
    if publisher:
        warcinfo_payload['publisher'] = publisher
    if operator:
        warcinfo_payload['operator'] = operator

    return warcinfo_payload


def create_string_payload(mime_dict, puid, result_dict, lang_cld):
    """Collect content mime, puid, encoding, and language to create record payload."""
    payload = []
    if mime_dict:
        payload.append('{0} {1}'.format(MIME_TITLE, mime_dict))
    if puid:
        payload.append('{0} {1}'.format(PUID_TITLE, puid))
    if result_dict.get('encoding'):
        payload.append('{0} {1}'.format(CHARSET_TITLE, result_dict))
    if lang_cld:
        payload.append('{0} {1}'.format(LANGUAGE_TITLE, lang_cld))
    return '\n'.join(payload)


def metadata_sidecar(archive_dir, warc_file, operator=None, publisher=None):
    start = time.time()

    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)

    logging.basicConfig(
        filename=os.path.join(archive_dir, 'sidecar.log'),
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s',
    )
    logging.getLogger(__name__)
    logging.info('Logging WARC metadata record information for %s', warc_file)

    # Create sidecar filename, adding 'meta' as extension.
    new_file = os.path.basename(warc_file)
    meta_file = re.sub(r'warc(\.gz)?$', 'warc.meta.gz', new_file)
    logging.info('Creating sidecar %s', meta_file)
    warc_file_path = os.path.join(archive_dir, meta_file)

    # Open the sidecar file to write in the metadata, open the warc file to get each record.
    with open(warc_file_path, 'ab') as output, open(warc_file, 'rb') as stream:
        record_count = 0
        total_records = 0
        text_mime = 0
        non_text = 0
        fido = ExtendFido()

        writer = WARCWriter(output, gzip=False)  # TODO: gzip will equal True
        warc_info = create_warcinfo_payload(new_file, operator, publisher)
        # Create warcinfo record and write it into sidecar.
        warcinfo_record = writer.create_warcinfo_record(meta_file, warc_info)
        writer.write_record(warcinfo_record)

        for record in ArchiveIterator(stream):
            total_records += 1
            if record.rec_type not in ['response', 'resource']:
                continue
            if 'text/dns' in record.rec_headers.get_header('Content-Type'):
                continue
            payload = io.BytesIO(record.content_stream().read())
            # The payload is how we find the important info. Skip record if empty.
            if not payload.read(1):
                continue
            url = record.rec_headers.get_header('WARC-Target-URI')
            record_date = record.rec_headers.get_header('WARC-Date')
            warcinfo_id = record.rec_headers.get_header('WARC-Warcinfo-ID')
            warcrecord_id = record.rec_headers.get_header('WARC-Record-ID')
            # Define specific warc_headers to include in sidecar.
            warc_dict = {'WARC-Date': record_date, 'WARC-Concurrent-ID': warcrecord_id}
            if warcinfo_id:
                warc_dict['WARC-Warcinfo-ID'] = warcinfo_id

            print(url)
            payload.seek(0)
            mime_dict, puid = find_mime_and_puid(fido, payload)
            result_dict = {}
            lang_cld = None
            # If these text formats are in the mime type(s), find the encoding and language.
            if TEXT_FORMAT_MIMES.search(' '.join(mime_dict.values())):
                payload.seek(0)
                bytes_payload = payload.read()
                result_dict = find_character_set(bytes_payload)
                lang_cld = find_language(bytes_payload)
                text_mime += 1
            else:
                non_text += 1
            string_payload = create_string_payload(mime_dict, puid, result_dict, lang_cld)
            if not string_payload:
                continue
            record_count += 1
            meta_record = writer.create_warc_record(url,
                                                    'metadata',
                                                    payload=io.BytesIO(string_payload.encode()),
                                                    warc_headers_dict=warc_dict
                                                    )
            writer.write_record(meta_record)
        # Delete sidecar file if we do not collect any records.
        if not record_count:
            os.remove(warc_file_path)
            logging.info('Deleted sidecar, no records to collect.')
        else:
            logging.info('Finished creating sidecar in %s',
                         str(timedelta(seconds=(time.time() - start))))
            logging.info('Determined sidecar information for %s response/resource record(s)',
                         record_count)
    print('Records with Mime Types: ' + str(text_mime + non_text))
    logging.info('Total Records for this WARC file: %s', total_records)
    print('Total Records for this WARC file:', total_records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'warc_file',
        action='store',
        help='A WARC file that will be used to generate a sidecar with metadata.'
    )
    parser.add_argument(
        'archive_dir',
        action='store',
        help='A directory where the sidecar and log will be stored.',
    )
    parser.add_argument(
        '--operator',
        action='store',
        default=None,
        help='A name or name and email address of the person running warc-metadata-sidecar.'
    )
    parser.add_argument(
        '--publisher',
        action='store',
        default='University of North Texas - Digital Projects Unit',
        help='The name of the institute or department to produce the metadata sidecar WARC file.'
    )
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file, args.operator, args.publisher)


if __name__ == '__main__':
    main()
