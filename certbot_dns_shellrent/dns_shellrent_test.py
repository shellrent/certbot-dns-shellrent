"""Tests for certbot_dns_shellrent.dns_shellrent."""

import unittest

import mock
import json
import requests_mock

from certbot import errors
from certbot.compat import os
from certbot.errors import PluginError
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

FAKE_USER = "remoteuser"
FAKE_TOKEN = "faketoken"
FAKE_ENDPOINT = "mock://endpoint"


class AuthenticatorTest(test_util.TempDirTestCase, dns_test_common.BaseAuthenticatorTest):
    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_shellrent.dns_shellrent import Authenticator

        path = os.path.join(self.tempdir, "file.ini")
        dns_test_common.write(
            {
                "shellrent_username": FAKE_USER,
                "shellrent_token": FAKE_TOKEN,
                "shellrent_endpoint": FAKE_ENDPOINT,
            },
            path,
        )

        super(AuthenticatorTest, self).setUp()
        self.config = mock.MagicMock(
            shellrent_credentials=path, shellrent_propagation_seconds=0
        )  # don't wait during tests

        self.auth = Authenticator(self.config, "shellrent")

        self.mock_client = mock.MagicMock()
        # _get_shellrent_client | pylint: disable=protected-access
        self.auth._get_shellrent_client = mock.MagicMock(return_value=self.mock_client)

    def test_perform(self):
        self.auth.perform([self.achall])

        expected = [
            mock.call.add_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        # _attempt_cleanup | pylint: disable=protected-access
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [
            mock.call.del_txt_record(
                DOMAIN, "_acme-challenge." + DOMAIN, mock.ANY
            )
        ]
        self.assertEqual(expected, self.mock_client.mock_calls)


class ShellrentClientTest(unittest.TestCase):
    record_name = "foo"
    record_content = "bar"

    def setUp(self):
        from certbot_dns_shellrent.dns_shellrent import _ShellrentClient

        self.adapter = requests_mock.Adapter()

        self.client = _ShellrentClient(FAKE_ENDPOINT, FAKE_USER, FAKE_TOKEN)
        self.client.session.mount("mock", self.adapter)

    def _register_response(self, ep_id, data={}, message="", additional_matcher=None, **kwargs):
        resp = {"error": 0, "title": "", "message": message, "data": data}
        if message:
            resp["error"] = 2
        # print(json.dumps(resp))
        # print("FAKE_ENDPOINT: {}/{}".format(FAKE_ENDPOINT, ep_id))

        self.adapter.register_uri(
            requests_mock.ANY,
            "{0}/{1}".format(FAKE_ENDPOINT, ep_id),
            text=json.dumps(resp),
            **kwargs
        )

    def test_add_txt_record(self):
        self._register_response("purchase", data=['123','124'])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124", data={'id':124 ,'domain_id': 125 })
        self._register_response("/domain/details/125", data={'domain_name': DOMAIN ,'id': '125' })
        self._register_response("dns_record/index/125", data=['1234','1235'])
        self._register_response("dns_record/details/125/1234", data={'id':'12346','type':'CNAME','host':'www','destination':'test_domain.com'})
        self._register_response("dns_record/details/125/1235", data={'id':'12356','type':'TXT','host': 'www2','destination': 'destination2.com'})
        self._register_response("dns_record/store/125")
        self.client.add_txt_record(
            DOMAIN, self.record_name, self.record_content
        )

    def test_add_txt_record_fail_on_insert_record(self):
        self._register_response("purchase", data=['123','124'])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124", data={'id':124 ,'domain_id': 125 })
        self._register_response("/domain/details/125", data={'domain_name': DOMAIN ,'id': '125' })
        self._register_response("dns_record/index/125", data=['1234','1235'])
        self._register_response("dns_record/details/125/1234", data={'id':'12346','type':'CNAME','host':'www','destination':'test_domain.com'})
        self._register_response("dns_record/details/125/1235", data={'id':'12356','type':'TXT','host': 'www2','destination': 'destination2.com'})
        self._register_response("dns_record/store/125", message="Error on insert" )
        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content
            )

    def test_add_txt_record_fail_to_find_domain(self):
        self._register_response("purchase", message="", data=["123","124"])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124")
        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content
            )

    def test_add_txt_record_fail_to_authenticate(self):
        self._register_response("purchase", message="Token di autorizzazione non valido")
        with self.assertRaises(errors.PluginError):
            self.client.add_txt_record(
                DOMAIN, self.record_name, self.record_content
            )

    def test_del_txt_record(self):
        self._register_response("purchase", data=['123','124'])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124", data={'id':124 ,'domain_id': 125 })
        self._register_response("/domain/details/125", data={'domain_name': DOMAIN ,'id': '125' })
        self._register_response("dns_record/index/125", data=['1234','1235'])
        self._register_response("dns_record/details/125/1234", data={'id':'12346','type':'CNAME','host':'www','destination':'test_domain.com'})
        self._register_response("dns_record/details/125/1235", data={'id':'12356','type':'TXT','host': self.record_name,'destination': self.record_content})
        self.client.del_txt_record(
            DOMAIN, self.record_name, self.record_content
        )

    def test_del_txt_record_no_error_on_fail_to_find_record(self):
        self._register_response("purchase", data=['123','124'])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124", data={'id':124 ,'domain_id': 125 })
        self._register_response("/domain/details/125", data={'domain_name': DOMAIN ,'id': '125' })
        self._register_response("dns_record/index/125", data=['1234','1235'])
        self._register_response("dns_record/details/125/1234", data={'id':'12346','type':'CNAME','host':'www','destination':'test_domain.com'})
        self._register_response("dns_record/details/125/1235", data={'id':'12356','type':'TXT','host': 'www2','destination': 'destination2.com'})
        self.client.del_txt_record(
            DOMAIN, self.record_name, self.record_content
        )

    def test_del_txt_record_fail_to_find_domain(self):
        self._register_response("purchase", message="", data=["123","124"])
        self._register_response("/purchase/details/123")
        self._register_response("/purchase/details/124")
        with self.assertRaises(errors.PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content
            )

    def test_del_txt_record_fail_to_authenticate(self):
        self._register_response("purchase", message="Token di autorizzazione non valido")
        with self.assertRaises(errors.PluginError):
            self.client.del_txt_record(
                DOMAIN, self.record_name, self.record_content
            )


if __name__ == "__main__":
    unittest.main()  # pragma: no cover
