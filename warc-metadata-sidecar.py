import argparse
import io
import os
import re

# import cchardet as chardet  # https://pypi.org/project/cchardet/
import chardet
# import cld3
import pycld2 as cld2
from fido.fido import Fido
from warcio.archiveiterator import ArchiveIterator
from warcio.recordloader import ArcWarcRecord
from warcio.warcwriter import WARCWriter


class ExtendFido(Fido):
    """ A class that extends Fido to override some methods."""

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
        for (f, sig_name) in matches:
            puid = self.get_puid(f)
            mime = f.find('mime')
            mimetype = mime.text if mime is not None else None
            self.puid = puid
            self.mime = mimetype


def metadata_sidecar(archive_dir, warc_file):
    fido = ExtendFido()
    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)
    warc_file_path = os.path.join(archive_dir, warc_file)
    meta_file = re.sub('warc(\.gz)?$', 'warc.meta', warc_file_path)  # 2nd arg will be 'warc.meta.gz'
    # print(meta_file)

    with open(meta_file, 'ab') as output:

        with open(warc_file, 'rb') as stream:
            record_count = 0
            text_html = 0
            non_text = 0
            non_mime = 0
            # open warc file and gather metadata to store in sidecar
            for record in ArchiveIterator(stream):
                if record.rec_type == 'response':  # ['response', 'resource']:
                    record_count += 1
                    url = record.rec_headers.get_header('WARC-Target-URI')

                    # https://github.com/webrecorder/warcio/issues/64
                    rawPayload = io.BytesIO(record.raw_stream.read())
                    if record.http_headers:
                        recordCopy = ArcWarcRecord(record.format, record.rec_type,
                                                   record.rec_headers, rawPayload,
                                                   record.http_headers, record.content_type,
                                                   record.length)
                        decodedPayload = recordCopy.content_stream().read()
                        rawPayload.seek(0)
                    else:
                        decodedPayload = rawPayload

                    print(url)

                    fido.identify_stream(rawPayload, url)
                    puid = fido.puid
                    mime = fido.mime
                    print(puid, mime)

                    result = chardet.detect(decodedPayload)
                    print(result)

                    if mime:
                        if 'text' in mime or 'html' in mime:
                            text_html += 1
                            text = decodedPayload.decode('utf-8-sig', 'ignore')
                            isReliable, textBytesFound, details = cld2.detect(text)
                            lang_cld = {'reliable': isReliable, 'text-bytes': textBytesFound,
                                        'languages': {'name': details[0][0], 'code': details[0][1],
                                                      'text-covered': details[0][2],
                                                      'score': details[0][3]
                                                      }
                                        }
                            print(lang_cld)
                            string_payload = '{0} {1}\n{2} {3}\n{4} {5}\n{6} {7}'.format('Mimetype:',
                                                                                         mime,
                                                                                         'Preservation-Identifier:',
                                                                                         puid,
                                                                                         'Charset-Detected:',
                                                                                         result['encoding'],
                                                                                         'Languages-cld2:',
                                                                                         lang_cld
                                                                                         )
                        else:
                            non_text += 1
                            string_payload = '{0} {1}\n{2} {3}\n{4} {5}'.format('Mimetype:',
                                                                                mime,
                                                                                'Preservation-Identifier:',
                                                                                puid,
                                                                                'Charset-Detected:',
                                                                                result['encoding'],
                                                                                )
                    else:
                        non_mime += 1
                        string_payload = '{0} {1}\n{2} {3}\n{4} {5}'.format('Mimetype:',
                                                                            mime,
                                                                            'Preservation-Identifier:',
                                                                            puid,
                                                                            'Charset-Detected:',
                                                                            result['encoding'],
                                                                            )
                    byte_payload = bytearray(string_payload.encode())
                    writer = WARCWriter(output, gzip=False)  # gzip will equal True
                    meta_record = writer.create_warc_record(url,
                                                            'metadata',
                                                            payload=io.BytesIO(byte_payload)
                                                            )
                    meta_record.raw_stream.seek(0)
                    writer.write_record(meta_record)

                # else:
                #     print('Error with rec_type')

    print('Completed: ' + str(record_count) + ' Text/html: ' + str(text_html) + ' All Others: ' + str(non_text + non_mime))


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
        help='a directory where the sidecar will be stored',
    )
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file)


if __name__ == '__main__':
    main()
