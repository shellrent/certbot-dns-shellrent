"""DNS Authenticator for Shellrent."""
import json
import logging
import time

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Shellrent

    This Authenticator uses the Shellrent Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using Shellrent for DNS)."

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=60
        )
        add("credentials", help="Shellrent credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the Shellrent Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "Shellrent credentials INI file",
            {
                "endpoint": "URL of the Shellrent Remote API.",
                "username": "Username for Shellrent Remote API.",
                "token": "token for Shellrent Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_shellrent_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_shellrent_client().del_txt_record(
            domain, validation_name, validation
        )

    def _get_shellrent_client(self):
        return _ShellrentClient(
            self.credentials.conf("endpoint"),
            self.credentials.conf("username"),
            self.credentials.conf("token"),
        )

class _ShellrentClient(object):
    """
    Encapsulates all communication with the Shellrent Remote REST API.
    """

    def __init__(self, endpoint, username, token):
        logger.debug("creating shellrentclient")
        self.endpoint = endpoint
        self.username = username
        self.token = token
        self.AUTH_HEADER = {'Authorization': self.username+"."+self.token }
        self.session = requests.Session()

    def _api_request(self, directive, method, data):
        url = self._get_url(directive)
        resp = self.session.request(method, url, data=data, headers=self.AUTH_HEADER, timeout=20)
        logger.debug("API REquest to URL: %s", url)
        if resp.status_code != 200:
            raise errors.PluginError(
                "HTTP Error {} during API call {} with data: {}".format(resp.status_code, url, resp.json())
            )
        try:
            result = resp.json()
        except:
            raise errors.PluginError(
                "API response with non JSON to call {}: {}".format(url, resp.text)
            )

        if result["error"] == 0:
            return result
        elif result["error"] != 0:
            raise errors.PluginError(
                "API response with an error: {0}".format(result["message"])
            )
        else:
            raise errors.PluginError("API response unknown to call {}: {}".format(url, resp.text))

    def _get_url(self, directive):
        return "{0}/{1}".format(self.endpoint, directive)

    def add_txt_record(self, domain, record_name, record_content):
        """
        Add a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Shellrent API
        """
        zone_id, zone_name = self._find_managed_zone_id(domain)
      
        if zone_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        record = self.get_existing_txt(zone_id, record_name, record_content)
        if record is not None:
            logger.info("already there, id {0}".format(record["data"]["id"]))
            return
        logger.info("insert new txt record")
        self._insert_txt_record(zone_id, record_name, record_content)

    def del_txt_record(self, domain, record_name, record_content):
        """
        Delete a TXT record using the supplied information.

        :param str domain: The domain to use to look up the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :raises certbot.errors.PluginError: if an error occurs communicating with the Shellrent API
        """
        zone_id, zone_name = self._find_managed_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError("Domain not known")
        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        o_record_name = record_name
        record_name = record_name.replace(zone_name, "")[:-1]
        logger.debug(
            "using record_name: %s from original: %s", record_name, o_record_name
        )
        record = self.get_existing_txt(zone_id, record_name, record_content)
        if record is not None:
            if record["data"]["destination"] == record_content:
                logger.debug("delete TXT record: %s", record["data"]["id"])
                self._delete_txt_record(zone_id, record["data"]["id"])

    def _insert_txt_record(self, zone_id, record_name, record_content):
        data = {
            "type": "TXT",
            "host": record_name,
            "destination": record_content
        }
        logger.debug("insert with data: %s", data)
        self._api_request("dns_record/store/" + str(zone_id), "POST", json.dumps(data))

    def _delete_txt_record(self, zone_id, record_id):
        logger.debug("delete with data: %s", record_id)
        self._api_request("dns_record/remove/" + str(zone_id) + "/" + str(record_id), "DELETE", "")

    def _find_managed_zone_id(self, domain):
        """
        Find the managed zone for a given domain.

        :param str domain: The domain for which to find the managed zone.
        :returns: The ID of the managed zone, if found.
        :rtype: str
        :raises certbot.errors.PluginError: if the managed zone cannot be found.
        """
        zone_dns_name_guesses = dns_common.base_domain_name_guesses(domain)

        purchases_list = self._api_request("purchase", "GET", "")
        
        for purchase in purchases_list["data"]:
            purchase_detail = self._api_request("/purchase/details/"+ purchase , "GET", "")
            if "domain_id" in purchase_detail["data"]:
                domain_detail = self._api_request("/domain/details/" + str(purchase_detail["data"]["domain_id"])  , "GET", "")
                for zone_name in zone_dns_name_guesses:
                    # get the zone id
                    if zone_name == domain_detail["data"]["domain_name"]:
                        logger.debug("looking for zone: %s", zone_name)
                        zone_id = domain_detail["data"]["id"]
                        return zone_id, zone_name
                    else:
                        pass

        return None, None

    def get_existing_txt(self, zone_id, record_name, record_content):
        """
        Get existing TXT records for the record name.

        If an error occurs while requesting the record set, it is suppressed
        and None is returned.

        :param str zone_id: The ID of the managed zone.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').

        :returns: TXT record value or None
        :rtype: `string` or `None`

        """

        zone_records = self._api_request("dns_record/index/" + str(zone_id), "GET", "")
        for record_id in zone_records["data"]:
            record_detail = self._api_request("dns_record/details/" + str(zone_id) + "/" + str(record_id) , "GET", "")
  
            if ( record_detail["data"]["host"] == record_name and record_detail["data"]["type"] == "TXT" and record_detail["data"]["destination"] == record_content ):
                return record_detail
  
        return None
