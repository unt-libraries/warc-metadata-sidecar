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
            if not readbuffer:  # this also works with if readbuffer == b'':
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
    print(fido.puid, fido.mime)


def find_character_set(bytes_payload):
    """Find the character set of the payload using chardet."""
    result = chardet.detect(bytes_payload)
    result_dict = {'encoding': result['encoding'],
                   'confidence': result['confidence']
                   }
    print(result)
    return result_dict


def find_language(bytes_payload):
    """Find the language of the payload using pycld2."""
    is_reliable, text_bytes_found, details = cld2.detect(bytes_payload.decode('utf-8', 'replace'),
                                                         bestEffort=True)
    new_list = []
    print(details)
    # details seems to always return 3, if the language is 'Unknown' we don't need to list it
    for item in details:
        if 'Unknown' not in item:
            new_list.append({
                'name': item[0],
                'code': item[1],
                'text-covered': item[2],
                'score': item[3]})
    if len(new_list) is not 0:
        lang_cld = {'reliable': is_reliable,
                    'text-bytes': text_bytes_found,
                    'languages': new_list}
        return lang_cld
    else:
        return None


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

    new_file = os.path.basename(warc_file)
    meta_file = re.sub('warc(\.gz)?$', 'warc.meta.gz', new_file)
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
        total_records = 0
        text_mime = 0
        non_text = 0
        non_mime = 0
        for record in ArchiveIterator(stream):
            total_records +=1
            url = record.rec_headers.get_header('WARC-Target-URI')
            payload = io.BytesIO(record.content_stream().read())
            if record.rec_type not in ['response', 'resource']:
                continue
            payload.seek(0)
            if len(payload.read()) == 0:
                print(url)
                print(len(payload.read()))
                continue
            if 'text/dns' in record.rec_headers.get_header('Content-Type'):
                continue
            record_count += 1
            record_date = record.rec_headers.get_header('WARC-Date')
            warcinfo_id = record.rec_headers.get_header('WARC-Warcinfo-ID')
            warcrecord_id = record.rec_headers.get_header('WARC-Record-ID')
            # define specific warc_headers to include in sidecar
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
                    print(lang_cld)
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

            writer = WARCWriter(output, gzip=False)  # gzip will equal True
            # if record_count == 1:
            #     warcinfo_record = writer.create_warcinfo_record(new_file, 'need some info here')
            #     writer.write_record(warcinfo_record)
            meta_record = writer.create_warc_record(url,
                                                    'metadata',
                                                    payload=io.BytesIO(string_payload.encode()),
                                                    warc_headers_dict=warc_dict
                                                    )
            writer.write_record(meta_record)

        logging.info('Found %s record(s)', record_count)
    logging.info('Finished creating sidecar in %s', str(timedelta(seconds=(time.time() - start))))
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
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file)


if __name__ == '__main__':
    main()
