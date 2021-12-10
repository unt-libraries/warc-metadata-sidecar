import argparse
import os
import sys

from chardet.universaldetector import UniversalDetector
from warcio.archiveiterator import ArchiveIterator
from fido.fido import Fido


class FixBytesBlock(Fido):
    """ A class that extends Fido to overide some methods."""

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
    fido = FixBytesBlock()
    if not os.path.isdir(archive_dir):
        os.mkdir(archive_dir)

    with open(warc_file, 'rb') as stream:
        record_count = 0
        # open warc file and gather metadata to store in sidecar
        for record in ArchiveIterator(stream):
            # if record.rec_type == 'response':
            if record.rec_type in ['response', 'resource']:
                if record.format == 'warc':
                    record_count += 1
                    url = record.rec_headers.get_header('WARC-Target-URI')
                # this is only if we also process arc files
                elif record.format == 'arc':
                    url = record.rec_headers.get_header('uri')
                
                print(url)
                
                fido.identify_stream(record.raw_stream, url)
                print(fido.puid, fido.mime)
                puid = fido.puid
                mime = fido.mime

                detector = UniversalDetector()
                for line in record.content_stream().read():
                    detector.feed(line)
                    if detector.done: break
                detector.close()
                print(detector.result)
                   
            # else:
            #     print('Error with rec_type')
            #     print(record.rec_type)
            
        # create sidecar and store data and save new file
        # maybe using warcio warcwriter create_warc_record

    print('Completed')
    print(record_count)

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
    # not sure if arg is needed for file name since it should techincally be the same as the warc file, but with added extension
    args = parser.parse_args()
    metadata_sidecar(args.archive_dir, args.warc_file)


if __name__ == '__main__':
    main()
