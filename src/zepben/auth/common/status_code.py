#  Copyright $year Zeppelin Bend Pty Ltd
#
#  This Source Code Form is subject to the terms of the Mozilla Public
#  License, v. 2.0. If a copy of the MPL was not distributed with this
#  file, You can obtain one at https://mozilla.org/MPL/2.0/.
from enum import Enum

__all__ = ["StatusCode"]


class StatusCode(Enum):

    OK = 200
    """ Successful """

    MALFORMED_TOKEN = 400
    """ Token was malformed """

    UNAUTHENTICATED = 403
    """ Failed to authenticate """

    PERMISSION_DENIED = 403
    """ Failed to authenticate, token didn't have required claims """

    NOT_FOUND = 404
    """ Resource/service not found """

    UNKNOWN = 500
    """ All other errors """
