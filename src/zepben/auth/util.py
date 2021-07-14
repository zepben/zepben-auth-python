#  Copyright 2020 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.

from yurl import URL

__all__ = ["construct_url"]


def construct_url(
    protocol: str = None,
    host: str = "localhost",
    port: int = None,
    path: str = None
) -> str:
    for split_host in host.split(":"):
        if (split_host != "http" and split_host != "https" and split_host.isnumeric() == False):
            host = split_host
    return (URL(url=host) if URL(url=host).host else URL(host=host)) \
        .replace(scheme=protocol, port=port, path=path).as_string()
