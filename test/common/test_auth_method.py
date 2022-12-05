#  Copyright 2022 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from zepben.auth import AuthMethod


def test_auth_method():
    assert len(AuthMethod) == 4
    assert AuthMethod.NONE.value == "NONE"
    assert AuthMethod.SELF.value == "self"
    assert AuthMethod.AUTH0.value == "AUTH0"
    assert AuthMethod.OAUTH.value == "OAUTH"
