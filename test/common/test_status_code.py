#  Copyright 2022 Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from zepben.auth.common.status_code import StatusCode


def test_status_code():
    assert StatusCode.OK.value == 200
    assert StatusCode.MALFORMED_TOKEN.value == 400
    assert StatusCode.UNAUTHENTICATED.value == 403
    assert StatusCode.PERMISSION_DENIED.value == 403
    assert StatusCode.NOT_FOUND.value == 404
    assert StatusCode.UNKNOWN.value == 500
