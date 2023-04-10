import io
import os
from logging import INFO
from unittest.mock import patch

import merge_cdxj


CDXJ = io.StringIO('com,example) 20091111212121 \
                   {"url": "http://www.example.com", "mime": "text/html"}')

MERGED_DICT = {'com,example) 20091111212121': {'url': 'http://www.example.com',
                                               'mime': 'text/html',
                                               'mime-detected': 'text/html',
                                               'charset': 'ascii',
                                               'languages': 'eng',
                                               'soft-404-detected': 0.08195022044249829}}

META_DICT = {'com,example) 20091111212121':
             {'Identified-Payload-Type': {'fido': 'text/html',
                                          'python-magic': 'text/html'},
              'Preservation-Identifier': 'fmt/96',
              'Charset-Detected': {'encoding': 'ascii',
                                   'confidence': 1.0},
              'Languages-cld2': {'reliable': True,
                                 'text-bytes': 4272,
                                 'languages': [{'name': 'ENGLISH',
                                                'code': 'en',
                                                'text-covered': 99,
                                                'score': 971.0}]},
              'Soft-404-Detected': 0.08195022044249829}}

MERGED_LIST = ['com,example) 20091111212121 {"url": "http://www.example.com", '
               '"mime": "text/html", "mime-detected": "text/html", '
               '"puid": "fmt/96", "charset": "ascii", '
               '"languages": "eng", "soft-404-detected": 0.08195022044249829}\n']

META_FILE = io.StringIO('com,example) 20091111212121 {"Identified-Payload-Type": \
                                {"fido": "text/html", "python-magic": "text/html"}, \
                                "Preservation-Identifier": "fmt/96", "Charset-Detected": \
                                {"encoding": "ascii", "confidence": 1.0}, \
                                "Languages-cld2": {"reliable": true, "text-bytes": 4272,\
                                "languages": [{"name": "ENGLISH", "code": "en",\
                                "text-covered": 99, "score": 971.0}]},\
                                "Soft-404-Detected": 0.08195022044249829}', newline='\n')


def test_get_alpha3_language_codes():
    lang_list = [{'name': 'DANISH', 'code': 'da', 'text-covered': 53, 'score': 430.0},
                 {'name': 'ENGLISH', 'code': 'en', 'text-covered': 46, 'score': 527.0}]
    lang_codes = merge_cdxj.get_alpha3_language_codes(lang_list)
    assert lang_codes == 'dan,eng'


def test_not_alpha3_language_code():
    unknown_lang = [{'name': 'ENGLISH', 'code': 'en', 'text-covered': 46, 'score': 527.0},
                    {'name': 'X_Nko', 'code': 'xx-Nkoo', 'text-covered': 10, 'score': 1024.0}]
    lang_codes = merge_cdxj.get_alpha3_language_codes(unknown_lang)
    assert lang_codes == 'eng'


@patch('merge_cdxj.get_alpha3_language_codes')
def test_get_all_sidecar_fields(m_alpha):
    m_alpha.return_value = 'eng'
    lang_list = [{'name': 'ENGLISH', 'code': 'en', 'text-covered': 99, 'score': 1209.0}]
    original_obj = {'mime': 'text/html'}
    meta_obj = {'Identified-Payload-Type': {'fido': 'application/xhtml+xml',
                                            'python-magic': 'text/html'},
                'Preservation-Identifier': 'fmt/102',
                'Charset-Detected': {'encoding': 'ascii', 'confidence': 1.0},
                'Languages-cld2': {'reliable': True, 'text-bytes': 1218,
                                   'languages': [{'name': 'ENGLISH',
                                                  'code': 'en',
                                                  'text-covered': 99,
                                                  'score': 1209.0}]},
                'Soft-404-Detected': 0.03782088786303804}
    actual = merge_cdxj.get_sidecar_fields(original_obj, meta_obj)
    assert actual['mime-detected'] != 'application/xhtml+xml'
    assert actual == {'mime': 'text/html', 'mime-detected': 'text/html', 'puid': 'fmt/102',
                      'charset': 'ascii', 'languages': 'eng', 
                      'soft-404-detected': 0.03782088786303804}
    m_alpha.assert_called_once_with(lang_list)


@patch('merge_cdxj.get_alpha3_language_codes')
def test_get_sidecar_fields(m_alpha):
    original_obj = {'mime': 'image/gif'}
    meta_obj = {'Identified-Payload-Type': {'fido': 'image/gif'},
                'Preservation-Identifier': 'fmt/4'}
    actual = merge_cdxj.get_sidecar_fields(original_obj, meta_obj)
    assert actual == {'mime': 'image/gif', 'mime-detected': 'image/gif', 'puid': 'fmt/4'}
    m_alpha.assert_not_called()


@patch('merge_cdxj.get_alpha3_language_codes')
def test_merge_meta_fields(m_lang):
    m_lang.return_value = 'eng'
    lang_array = [{'name': 'ENGLISH', 'code': 'en', 'text-covered': 99, 'score': 971.0}]
    cdxj = io.StringIO('com,example) 20091111212121 {"url": "http://www.example.com", \
                                                     "mime": "text/html"}\n', newline='\n')
    original, edited, non_edited = merge_cdxj.merge_meta_fields(META_DICT, cdxj)
    assert original == MERGED_LIST
    assert not non_edited
    assert edited == 1
    m_lang.assert_called_once_with(lang_array)


@patch('merge_cdxj.get_sidecar_fields')
def test_merge_meta_fields_non_edited(m_fields):
    m_fields.return_value = {'url': 'http://www.example.com',
                             'mime': 'text/html',
                             'mime-detected': 'text/html',
                             'charset': 'ascii',
                             'languages': 'eng',
                             'soft-404-detected': 0.08195022044249829}
    cdxj = io.StringIO('com,example) 20091111212121 {"url": "http://www.example.com", \
                                                     "mime": "text/html"}\n'
                       'com,abc) 20091111212131 {"url": "http://www.abc.com", '
                       '"mime": "text/xml"}\n', newline='\n')
    merged_list = ['com,example) 20091111212121 {"url": "http://www.example.com", '
                   '"mime": "text/html", "mime-detected": "text/html", '
                   '"charset": "ascii", "languages": "eng", '
                   '"soft-404-detected": 0.08195022044249829}\n',
                   'com,abc) 20091111212131 {"url": "http://www.abc.com", "mime": "text/xml"}\n']
    original, edited, non_edited = merge_cdxj.merge_meta_fields(META_DICT, cdxj)
    assert original == merged_list
    assert non_edited == 1
    assert edited == 1
    m_fields.assert_called_once()


@patch('merge_cdxj.get_alpha3_language_codes')
def test_merge_meta_fields_with_duplicate(m_alpha):
    m_alpha.return_value = 'eng'
    cdxj = io.StringIO('com,example) 20091111212121 {"url": "http://www.example.com", \
                                                     "mime": "text/html"}\n'
                       'com,example) 20091111212121 {"url": "http://www.example.com", '
                       '"mime": "text/xml"}\n', newline='\n')
    merged_list = ['com,example) 20091111212121 {"url": "http://www.example.com", '
                   '"mime": "text/html", "mime-detected": "text/html", '
                   '"puid": "fmt/96", '
                   '"charset": "ascii", "languages": "eng", '
                   '"soft-404-detected": 0.08195022044249829}\n',
                   'com,example) 20091111212121 {"url": "http://www.example.com", '
                   '"mime": "text/xml", "mime-detected": "text/html", '
                   '"puid": "fmt/96", '
                   '"charset": "ascii", "languages": "eng", '
                   '"soft-404-detected": 0.08195022044249829}\n']
    original, edited, non_edited = merge_cdxj.merge_meta_fields(META_DICT, cdxj)
    assert original == merged_list
    assert not non_edited
    assert edited == 2
    m_alpha.assert_called()


def test_create_dict_from_meta():
    actual_dict = merge_cdxj.create_dict_from_meta(META_FILE)
    assert actual_dict == META_DICT


def test_create_cdxj_path(tmpdir):
    cdxj_path = merge_cdxj.create_cdxj_path('home/file.cdxj', str(tmpdir))
    expected_path = os.path.join(tmpdir / 'file_merged.cdxj')
    assert cdxj_path == expected_path


@patch('merge_cdxj.create_dict_from_meta')
@patch('merge_cdxj.merge_meta_fields')
def test_merge_cdxj2(m_merge_meta, m_create_dict, caplog, tmpdir):
    test_dir = os.path.dirname(__file__)
    meta_file = os.path.join(test_dir, 'meta.cdxj')
    cdxj_file = os.path.join(test_dir, 'warc_1.cdxj')
    expected = ['com,example) 20091111212121 {"url": "http://www.example.com", '
                '"mime": "text/html", "mime-detected": "text/html", "puid": "fmt/96", '
                '"charset": "ascii", "languages": "eng", '
                '"soft-404-detected": 0.08195022044249829}\n']
    caplog.set_level(INFO)
    m_create_dict.return_value = META_DICT
    m_merge_meta.return_value = MERGED_LIST, 1, 0
    merge_cdxj.merge_cdxjs(meta_file, cdxj_file, tmpdir)
    merged_file_path = os.path.join(tmpdir / 'warc_1_merged.cdxj')
    assert 'Logging CDXJ merge information for {} and {}'.format(cdxj_file,
                                                                 meta_file) in caplog.text
    assert 'Total merged records: 1' in caplog.text
    assert merged_file_path in tmpdir.listdir()
    m_create_dict.assert_called_once()
    m_merge_meta.assert_called_once()
    with open(merged_file_path, 'r') as m_file:
        lines = m_file.readlines()
        assert lines == expected
