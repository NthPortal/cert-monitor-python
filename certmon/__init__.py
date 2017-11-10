import logging
import sys
from typing import List, Callable, Any

import certstream

_Ctx = certstream.core.Context
CertStreamCallback = Callable[[Any, _Ctx], None]
StringMatcher = Callable[[str], bool]


def monitor(matchers: List[StringMatcher], callback: CertStreamCallback) -> None:
    """

    :param matchers:
    :param callback:
    :return:
    """

    def handle(message, context: _Ctx) -> None:
        for d in message["data"]["leaf_cert"]["all_domains"]:
            domain = str(d)
            for matcher in matchers:
                if matcher(domain):
                    callback(message, context)
                    return

    certstream.listen_for_events(handle)


def _matching_domain_ending_in(name: str) -> StringMatcher:
    def matcher(domain: str):
        return domain.endswith(name)

    return matcher


def monitor_domains_ending_in(domain_endings: List[str], callback: CertStreamCallback) -> None:
    matchers = [_matching_domain_ending_in(ending) for ending in domain_endings]
    monitor(matchers, callback)


def _basic_monitor_domains_ending_in(domain_endings: List[str]) -> None:
    def callback(message, _: _Ctx) -> None:
        for d in message["data"]["leaf_cert"]["all_domains"]:
            domain = str(d)
            for ending in domain_endings:
                if domain.endswith(ending):
                    cert_auth = message["data"]["chain"][0]["subject"]["CN"]
                    logging.info(f"Certificate issued for    {domain:40} by    {cert_auth}")
                    break

    monitor_domains_ending_in(domain_endings, callback)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        raise ValueError("missing list of domain suffixes")
    else:
        logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.INFO)
        _basic_monitor_domains_ending_in(sys.argv[1:])
