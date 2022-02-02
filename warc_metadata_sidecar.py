import argparse
import io
import logging
import os
import pkg_resources
import re
import socket
import time
from datetime import timedelta

import chardet
import pycld2 as cld2
from fido.fido import Fido
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter


class ExtendFido(Fido):
    """A class that extends Fido to override some methods."""
    def blocking_read(self, file, bytes_to_read):
        """This method is used to get the end of the buffer.

        A known issue is that the stream hangs when identify_stream is called. The if statement
        helps break out when end of file is reached.
        """
        # https://github.com/openpreserve/fido/blob/master/fido/fido.py#L510
        bytes_read = 0
        buffer = b''
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            buffer += readbuffer
            bytes_read = len(buffer)
            if not readbuffer:  # Also works with if readbuffer == b'':
                break
        return buffer

    def print_matches(self, fullname, matches, delta_t, matchtype=''):
        """This method prints out information for each match.

        We override the method in order to save the mimetype and puid to the fido object.
        """
        # https://github.com/openpreserve/fido/blob/master/fido/fido.py#L272
        if not matches:
            self.puid = None
            self.mime = None
            return
        match_format, _ = matches[0]
        mime = match_format.find('mime')
        self.mime = mime.text if mime is not None else None
        self.puid = self.get_puid(match_format)


def find_mime_and_puid(fido, payload, url):
    """Find the mimetype and preservation identifier using fido."""
    fido.identify_stream(payload, url)


def find_character_set(bytes_payload):
    """Find the character set of the payload using chardet."""
    result = chardet.detect(bytes_payload)
    result_dict = {'encoding': result['encoding'],
                   'confidence': result['confidence']
                   }
    return result_dict


def find_language(bytes_payload):
    """Find the language of the payload using pycld2."""
    is_reliable, text_bytes_found, details = cld2.detect(bytes_payload.decode('utf-8', 'replace'),
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
    if len(new_list):
        lang_cld = {'reliable': is_reliable,
                    'text-bytes': text_bytes_found,
                    'languages': new_list}
        return lang_cld
    else:
        return None


def create_warcinfo_payload(payload, operator, publisher, new_file, version):
    payload.seek(0)
    info_payload = payload.read()
    warcinfo = info_payload.decode("utf-8")
    warc_list = re.split('\r\n|: ', warcinfo)
    hostname = socket.gethostname()
    warc_doc = 'http://bibnum.bnf.fr/WARC/WARC_ISO_28500_version1_latestdraft.pdf'
    warcinfo_payload = {'software': 'warc-metadata-sidecar/' + version,
                        'hostname': hostname,
                        'ip': socket.gethostbyname(hostname),
                        'conformsTo': warc_doc,
                        'description': 'WARC metdata sidecar for ' + new_file,
                        'publisher': publisher}
    if operator:
        warcinfo_payload['operator'] = operator
    if 'isPartOf' in warc_list:
        list_index = warc_list.index('isPartOf')
        is_part_of = warc_list[list_index + 1]
        warcinfo_payload['isPartOf'] = is_part_of

    return warcinfo_payload


def metadata_sidecar(archive_dir, warc_file, operator=None,
                     publisher='University of North Texas - Digital Projects Unit'):
    start = time.time()
    version = pkg_resources.require("warc-metadata-sidecar")[0].version

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
    meta_file = re.sub('warc(\.gz)?$', 'warc.meta.gz', new_file)
    logging.info('Creating sidecar %s', meta_file)
    warc_file_path = os.path.join(archive_dir, meta_file)

    fido = ExtendFido()
    mime_title = 'Identified-Payload-Type:'
    puid_title = 'Preservation-Identifier:'
    charset_title = 'Charset-Detected:'
    language_title = 'Languages-cld2:'

    # Open the sidecar file to write in the metadata, open the warc file to get each record.
    with open(warc_file_path, 'ab') as output, open(warc_file, 'rb') as stream:
        record_count = 0
        total_records = 0
        text_mime = 0
        non_text = 0
        non_mime = 0
        for record in ArchiveIterator(stream):
            total_records += 1
            url = record.rec_headers.get_header('WARC-Target-URI')
            payload = io.BytesIO(record.content_stream().read())
            if not record_count:  # and record.rec_type == 'warcinfo':
                rec_type = record.rec_type
                warc_info = create_warcinfo_payload(payload, operator, publisher,
                                                    new_file, version)
                # Write warcinfo record into sidecar.
                writer = WARCWriter(output, gzip=False)  # TODO: gzip will equal True
                warcinfo_record = writer.create_warcinfo_record(meta_file, warc_info)
                writer.write_record(warcinfo_record)
                record_count += 1
            if record.rec_type not in ['response', 'resource']:
                continue
            payload.seek(0)
            # The payload is how we find the important info. Skip record if empty.
            if not len(payload.read()):
                continue
            if 'text/dns' in record.rec_headers.get_header('Content-Type'):
                continue
            record_count += 1
            record_date = record.rec_headers.get_header('WARC-Date')
            warcinfo_id = record.rec_headers.get_header('WARC-Warcinfo-ID')
            warcrecord_id = record.rec_headers.get_header('WARC-Record-ID')
            # Define specific warc_headers to include in sidecar.
            warc_dict = {'WARC-Date': record_date, 'WARC-Concurrent-ID': warcrecord_id}
            if warcinfo_id:
                warc_dict['WARC-Warcinfo-ID'] = warcinfo_id

            print(url)
            payload.seek(0)
            find_mime_and_puid(fido, payload, url)

            if fido.mime:
                text_format_mimes = re.compile(r'(text|html|xml)')
                if text_format_mimes.search(fido.mime):
                    payload.seek(0)
                    bytes_payload = payload.read()
                    result_dict = find_character_set(bytes_payload)
                    lang_cld = find_language(bytes_payload)
                    text_mime += 1
                    if not lang_cld:
                        string_payload = '{0} {1}\n{2} {3}\n{4} {5}'.format(
                            mime_title, fido.mime,
                            puid_title, fido.puid,
                            charset_title, result_dict
                            )
                    else:
                        string_payload = '{0} {1}\n{2} {3}\n{4} {5}\n{6} {7}'.format(
                            mime_title, fido.mime,
                            puid_title, fido.puid,
                            charset_title, result_dict,
                            language_title, lang_cld
                            )
                else:
                    non_text += 1
                    string_payload = '{0} {1}\n{2} {3}'.format(
                        mime_title, fido.mime,
                        puid_title, fido.puid
                        )
            else:
                non_mime += 1
                string_payload = ''

            writer = WARCWriter(output, gzip=False)  # TODO: gzip will equal True
            meta_record = writer.create_warc_record(url,
                                                    'metadata',
                                                    payload=io.BytesIO(string_payload.encode()),
                                                    warc_headers_dict=warc_dict
                                                    )
            writer.write_record(meta_record)
        # Delete sidecar file if the only record is 'warcinfo'.
        if record_count == 1:
            if rec_type:
                os.remove(warc_file_path)
                logging.info('Deleted sidecar, no records to collect.')
        else:
            logging.info('Finished creating sidecar in %s',
                         str(timedelta(seconds=(time.time() - start))))
            logging.info('Found %s record(s)', record_count)
    print('Mimes: ' + str(text_mime + non_text) + ' Non Mimes: ' + str(non_mime))
    print('Total Records for this WARC file: ', total_records)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'warc_file',
        action='store',
        help='a WARC file that will be used to generate a sidecar with metadata'
    )
    parser.add_argument(
        'archive_dir',
        action='store',
        help='a directory where the sidecar and log will be stored',
    )
    parser.add_argument(
        '--operator',
        action='store',
        default=None,
        help='a name or name and email address of the person who created this WARC file'
    )
    parser.add_argument(
        '--publisher',
        action='store',
        default='University of North Texas - Digital Projects Unit',
        help='the name of the institute or department to produce the metadata sidecar WARC file'
    )
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file, args.operator, args.publisher)


if __name__ == '__main__':
    main()
