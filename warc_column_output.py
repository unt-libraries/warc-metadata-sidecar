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
import pycld2 as cld2
from fido.fido import Fido
from magic.compat import detect_from_content
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter


MIME_TITLE = 'Identified-Payload-Type:'
METHOD_TITLE = 'Payload-Type-Retrieval-Method:'
RETRIEVED_TITLE = 'Payload-Type-Retrieved-By:'
PUID_TITLE = 'Preservation-Identifier:'
CHARSET_TITLE = 'Charset-Detected:'
LANGUAGE_TITLE = 'Languages-cld2:'

BAD_CHARS = regex.compile(r'\p{Cc}|\p{Cs}|\p{Cn}')


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
            if not readbuffer:  # Also works with if readbuffer == b'':
                break
        return buffer

    def print_matches(self, fullname, matches, matchtype=''):
        """Override print_matches to store a mimetype and puid to the fido object."""
        # https://github.com/openpreserve/fido/blob/master/fido/fido.py#L272
        if not matches:
            self.mime = None
            self.puid = None
            self.matchtype = matchtype
            self.format_tool = 'Fido'
            return
        match_format, _ = matches[0]
        mime = match_format.find('mime')
        puid = None
        self.mime = mime.text if mime is not None else None
        # We only want puid from the content.
        if matchtype != 'extension':
            puid = self.get_puid(match_format)
        self.puid = puid if puid is not None else None
        self.matchtype = matchtype
        self.format_tool = 'Fido'

    # def identify_stream(self, stream, filename, extension=True):
    #     """Override identify_stream to get the matches for file content only."""
    #     bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream)
    #     self.current_filesize = bytes_read
    #     self.current_file = filename
    #     matches = self.match_formats(bofbuffer, eofbuffer)
    #     self.print_matches(self.current_file, matches, 'content')

    # temporary change
    def identify_content(self, stream, filename, extension=True):
        bofbuffer, eofbuffer, bytes_read = self.get_buffers(stream, length=None)
        self.current_filesize = bytes_read
        matches = self.match_formats(bofbuffer, eofbuffer)
        self.handle_matches(self.current_file, matches, "signature")
    def identify_extension(self, stream, filename, extension=True):
        if filename is not None:
            self.current_file = filename
            matches = self.match_extensions(self.current_file)
            self.handle_matches(self.current_file, matches, "extension")


# def find_mime_and_puid(fido, payload, url):
#     """Find the mimetype and preservation identifier using fido and python-magic."""
#     fido.identify_stream(payload, url)
#     # Using python-magic to find mimetype.
#     if not fido.mime:
#         payload.seek(0)
#         buffer = payload.read()
#         m = detect_from_content(buffer)
#         fido.mime = m.mime_type
#         fido.format_tool = 'python-magic'
#     # If we still haven't found the mimetype using the content, try by extension using Fido.
#     if not fido.mime:
#         new_file = os.path.basename(url)
#         matches = fido.match_extensions(new_file)
#         fido.print_matches(url, matches, 'extension')

#temporary change
def find_mime_and_puid(fido, payload, url):
    fido.identify_content(payload, url)
    fido.content_mime = fido.mime

    new_file = os.path.basename(url)
    fido.identify_extension(payload, new_file)
    fido.ext_mime = fido.mime

    payload.seek(0)
    buffer = payload.read()
    m = detect_from_content(buffer)
    fido.magic_mime = m.mime_type

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
        if 'Unknown' not in item:
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

        writer = WARCWriter(output, gzip=False)  # TODO: gzip will equal True
        warc_info = create_warcinfo_payload(new_file, operator, publisher)
        # Create warcinfo record and write it into sidecar.
        warcinfo_record = writer.create_warcinfo_record(meta_file, warc_info)
        writer.write_record(warcinfo_record)

        print("%s\t%s\t%s\t%s" % ('URL', 'Fido/Content', 'Fido/Extension', 'Python-Magic'))

        for record in ArchiveIterator(stream):
            fido = ExtendFido()
            total_records += 1
            url = record.rec_headers.get_header('WARC-Target-URI')
            payload = io.BytesIO(record.content_stream().read())
            if record.rec_type not in ['response', 'resource']:
                continue
            # The payload is how we find the important info. Skip record if empty.
            if not payload.read(1):
                continue
            if 'text/dns' in record.rec_headers.get_header('Content-Type'):
                continue
            record_date = record.rec_headers.get_header('WARC-Date')
            warcinfo_id = record.rec_headers.get_header('WARC-Warcinfo-ID')
            warcrecord_id = record.rec_headers.get_header('WARC-Record-ID')
            # Define specific warc_headers to include in sidecar.
            warc_dict = {'WARC-Date': record_date, 'WARC-Concurrent-ID': warcrecord_id}
            if warcinfo_id:
                warc_dict['WARC-Warcinfo-ID'] = warcinfo_id

            # print(url)
            payload.seek(0)
            find_mime_and_puid(fido, payload, url)
            print("%s\t%s\t%s\t%s" % (url, fido.content_mime, fido.ext_mime, fido.magic_mime))

            # temporary code
            if fido.content_mime:
                fido.mime = fido.content_mime
                fido.matchtype = 'content'
            elif fido.magic_mime:
                fido.mime = fido.magic_mime
                fido.matchtype = 'content'
                fido.format_tool = 'python-magic'

            puid = '\n{0} {1}'.format(PUID_TITLE, fido.puid) if fido.puid is not None else None
            if fido.mime:
                mime_str = '{0} {1}\n{2} {3}\n{4} {5}'.format(
                            MIME_TITLE, fido.mime,
                            METHOD_TITLE, fido.matchtype,
                            RETRIEVED_TITLE, fido.format_tool)
                string_payload = mime_str
                if puid:
                    string_payload += puid
                text_format_mimes = re.compile(r'(text|html|xml)')
                if text_format_mimes.search(fido.mime):
                    payload.seek(0)
                    bytes_payload = payload.read()
                    result_dict = find_character_set(bytes_payload)
                    lang_cld = find_language(bytes_payload)
                    text_mime += 1
                    if result_dict['encoding']:
                        char = '\n{0} {1}'.format(CHARSET_TITLE, result_dict)
                        string_payload += char
                    if lang_cld:
                        lang = '\n{0} {1}'.format(LANGUAGE_TITLE, lang_cld)
                        string_payload += lang
                else:
                    non_text += 1
            else:
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
            logging.info('Found %s record(s)', record_count)
    print('Mimes: ' + str(text_mime + non_text))
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
