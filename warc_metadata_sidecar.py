import argparse
import io
import logging
import os
import re
import time
from datetime import timedelta

import chardet
import pycld2 as cld2
from fido.fido import Fido
from warcio.archiveiterator import ArchiveIterator
from warcio.recordloader import ArcWarcRecord
from warcio.warcwriter import WARCWriter


class ExtendFido(Fido):
    """A class that extends Fido to override some methods."""
    def blocking_read(self, file, bytes_to_read):
        bytes_read = 0
        buffer = b''
        while bytes_read < bytes_to_read:
            readbuffer = file.read(bytes_to_read - bytes_read)
            buffer += readbuffer
            bytes_read = len(buffer)
            # break out if EOF is reached.
            if not readbuffer:  # this also works with if readbuffer == b'':
                break
        return buffer

    def print_matches(self, fullname, matches, delta_t, matchtype=''):
        if len(matches) == 0:
            self.puid = None
            self.mime = None
            return
        for (f, sig_name) in matches:
            puid = self.get_puid(f)
            mime = f.find('mime')
            mimetype = mime.text if mime is not None else None
            self.puid = puid
            self.mime = mimetype


def find_mime_and_puid(fido, rawPayload, url):
    """A method that uses fido to find the mimetype and preservation identifier."""
    fido.identify_stream(rawPayload, url)
    print(fido.puid, fido.mime)


def find_character_set(decodedPayload):
    """A method that uses chardet to find the character set of the payload."""
    result = chardet.detect(decodedPayload)
    result_dict = {'encoding': result['encoding'],
                   'confidence': result['confidence']
                   }
    print(result)
    return result_dict


def find_language(decodedPayload):
    """A method that uses pycld2 to find the language of the payload."""
    text = decodedPayload.decode('utf-8-sig', 'ignore')
    isReliable, textBytesFound, details = cld2.detect(text)
    lang_cld = {'reliable': isReliable,
                'text-bytes': textBytesFound,
                'languages': {
                    'name': details[0][0],
                    'code': details[0][1],
                    'text-covered': details[0][2],
                    'score': details[0][3]}
                }
    print(lang_cld)
    return lang_cld


def metadata_sidecar(archive_dir, warc_file):
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

    if '/' in warc_file:
        warc_list = warc_file.split('/')
        length = len(warc_list)
        new_file = warc_list[length-1]
        print(new_file)
        meta_file = re.sub('warc(\.gz)?$', 'warc.meta.gz', new_file)
    else:
        meta_file = re.sub('warc(\.gz)?$', 'warc.meta.gz', warc_file)
    logging.info('Creating sidecar %s', meta_file)
    warc_file_path = os.path.join(archive_dir, meta_file)

    fido = ExtendFido()
    mime_title = 'Identified-Payload-Type:'
    puid_title = 'Preservation-Identifier:'
    charset_title = 'Charset-Detected:'
    language_title = 'Languages-cld2:'

    # open the sidecar file to write in the metadata, open the warc file to get each record
    with open(warc_file_path, 'ab') as output, open(warc_file, 'rb') as stream:
        record_count = 0
        text_mime = 0
        non_text = 0
        non_mime = 0
        for record in ArchiveIterator(stream):
            url = record.rec_headers.get_header('WARC-Target-URI')
            if record.rec_type not in ['response', 'resource']:
                continue
            if 'text/dns' in record.rec_headers.get_header('Content-Type'):
                continue
            record_count += 1
            record_date = record.rec_headers.get_header('WARC-Date')
            warcinfo_id = record.rec_headers.get_header('WARC-Warcinfo-ID')
            warcrecord_id = record.rec_headers.get('WARC-Record-ID')
            # define specific warc_headers to include in sidecar
            warc_dict = {'WARC-Date': record_date, 'WARC-Concurrent-ID': warcrecord_id}
            if warcinfo_id:
                warc_dict['WARC-Warcinfo-ID'] = warcinfo_id

            # https://github.com/webrecorder/warcio/issues/64
            rawPayload = io.BytesIO(record.raw_stream.read())
            if record.http_headers:
                recordCopy = ArcWarcRecord(
                    record.format, record.rec_type,
                    record.rec_headers, rawPayload,
                    record.http_headers, record.content_type,
                    record.length
                    )
                decodedPayload = recordCopy.content_stream().read()
                rawPayload.seek(0)
            else:
                decodedPayload = rawPayload

            print(url)
            find_mime_and_puid(fido, rawPayload, url)
            result_dict = find_character_set(decodedPayload)

            if fido.mime:
                # using pycld2, if text, html or xml in mimetype find language in payload
                text_format_mimes = re.compile(r'(text|html|xml)')
                if text_format_mimes.search(fido.mime):
                    lang_cld = find_language(decodedPayload)
                    text_mime += 1
                    string_payload = '{0} {1}\n{2} {3}\n{4} {5}\n{6} {7}'.format(
                        mime_title, fido.mime,
                        puid_title, fido.puid,
                        charset_title, result_dict,
                        language_title, lang_cld
                        )
                elif result_dict['encoding'] is None:
                    non_text += 1
                    string_payload = '{0} {1}\n{2} {3}'.format(
                        mime_title, fido.mime,
                        puid_title, fido.puid,
                        )
                else:
                    non_text += 1
                    string_payload = '{0} {1}\n{2} {3}\n{4} {5}'.format(
                        mime_title, fido.mime,
                        puid_title, fido.puid,
                        charset_title, result_dict,
                        )
            elif result_dict['encoding'] is None:
                non_mime += 1
                string_payload = ''
            else:
                non_mime += 1
                string_payload = '{0} {1}'.format(charset_title, result_dict)

            byte_payload = bytearray(string_payload.encode())
            writer = WARCWriter(output, gzip=False)  # gzip will equal True
            meta_record = writer.create_warc_record(url,
                                                    'metadata',
                                                    payload=io.BytesIO(byte_payload),
                                                    warc_headers_dict=warc_dict
                                                    )
            writer.write_record(meta_record)

        logging.info('Found %s record(s)', record_count)
    logging.info('Finished creating sidecar in %s', str(timedelta(seconds=(time.time() - start))))
    print('Mimes: ' + str(text_mime + non_text) + ' Non Mimes: ' + str(non_mime))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'warc_file',
        action='store',
        help='a warc file that will be used to generate a sidecar with metadata'
    )
    parser.add_argument(
        'archive_dir',
        action='store',
        help='a directory where the sidecar and log will be stored',
    )
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file)


if __name__ == '__main__':
    main()
