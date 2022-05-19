import io
import os
from logging import INFO
from unittest.mock import MagicMock, patch, call

import merge_cdxj


CDXJ = io.StringIO('com,example) 20091111212121 \
                   {"url": "http://www.example.com", "mime": "text/html"}')

MERGED_DICT = {"com,example) 20091111212121": {"url": "http://www.example.com",
                                               "mime": "text/html",
                                               "mime-detected": "text/html",
                                               "charset": "ascii",
                                               "languages": "eng",
                                               "soft-404-detected": 0.08195022044249829}}

META_DICT = {'com,example) 20091111212121':
             {"Identified-Payload-Type": {"fido": "text/html",
                                          "python-magic": "text/html"},
              "Preservation-Identifier": "fmt/96",
              "Charset-Detected": {"encoding": "ascii",
                                   "confidence": 1.0},
              "Languages-cld2": {"reliable": True,
                                 "text-bytes": 4272,
                                 "languages": [{"name": "ENGLISH",
                                                "code": "en",
                                                "text-covered": 99,
                                                "score": 971.0}]},
              "Soft-404-Detected": 0.08195022044249829}}

MERGED_LIST = ['com,example) 20091111212121 {"url": "http://www.example.com", '
               '"mime": "text/html", "mime-detected": "text/html", '
               '"charset": "ascii", "languages": "eng", '
               '"soft-404-detected": 0.08195022044249829}\n']

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
    unknown_lang = [{'name': 'X_Nko', 'code': 'xx-Nkoo', 'text-covered': 10, 'score': 1024.0}]
    lang_codes = merge_cdxj.get_alpha3_language_codes(unknown_lang)
    assert lang_codes == ''


def test_get_sidecar_fields():
    original_obj = {'mime': 'text/html'}
    meta_obj = {"Identified-Payload-Type": {"fido": "image/gif", "python-magic": "image/gif"},
                "Preservation-Identifier": "fmt/4"}
    actual = merge_cdxj.get_sidecar_fields(original_obj, meta_obj)
    assert actual == {'mime': 'text/html', 'mime-detected': 'image/gif'}


def test_merge_meta_fields():
    cdxj = io.StringIO('com,example) 20091111212121 {"url": "http://www.example.com", \
                                                     "mime": "text/html"}\n', newline='\n')
    original, edited, non_edited = merge_cdxj.merge_meta_fields(META_DICT, cdxj)
    assert original == MERGED_LIST
    assert not non_edited
    assert edited == 1


def test_create_dict_from_meta():
    actual_dict = merge_cdxj.create_dict_from_meta(META_FILE)
    assert actual_dict == META_DICT


def test_create_cdxj_path(tmpdir):
    cdxj_path = merge_cdxj.create_cdxj_path('home/file.cdxj', str(tmpdir))
    expected_path = os.path.join(tmpdir / 'file_merged.cdxj')
    assert cdxj_path == expected_path


class Test_Merge_Cdxj:
    @patch('merge_cdxj.create_dict_from_meta')
    @patch('merge_cdxj.merge_meta_fields')
    @patch('builtins.open', spec=open)
    def test_merge_cdxj2(self, mock_open, m_merge_meta, m_create_dict, caplog, tmpdir):
        caplog.set_level(INFO)
        merged_file = io.StringIO()
        m_create_dict.return_value = META_DICT
        m_merge_meta.return_value = MERGED_LIST, 1, 0
        handle1 = MagicMock()
        handle1.__enter__.return_value = merged_file
        handle1.__exit__.return_value = False
        handle2 = MagicMock()
        handle2.__enter__.return_value = META_FILE
        handle2.__exit__.return_value = False
        handle3 = MagicMock()
        handle3.__enter__.return_value = CDXJ
        handle3.__exit__.return_value = False
        mock_open.side_effect = (handle1, handle2, handle3)
        merge_cdxj.merge_cdxjs('meta.cdxj', 'original.cdxj', tmpdir)
        assert 'Logging CDXJ merge information for original.cdxj and meta.cdxj' in caplog.text
        assert 'Total edited records: %s', 1 in caplog.text
        m_create_dict.assert_called_once_with(META_FILE)
        m_merge_meta.assert_called_once_with(META_DICT, CDXJ)
        calls = [call(tmpdir/'original_merged.cdxj', 'wt'),
                 call('meta.cdxj', 'r'),
                 call('original.cdxj', 'r')]
        mock_open.assert_has_calls(calls)
