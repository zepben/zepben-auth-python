#  Copyright $year Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from zepben.auth import construct_url

def test_construct_url():
    assert construct_url("htcpcp", "coffeepot", "/espresso", 1234) == "htcpcp://coffeepot:1234/espresso"
    assert construct_url("https", "example.com", "/") == "https://example.com/"
