name = "flask_jwt_consumer"

from pkg_resources import DistributionNotFound, get_distribution

try:
    __version__ = get_distribution(__name__).version
except DistributionNotFound:
    __version__ = "0.0.0"


from .flask_jwt_consumer import JWTConsumer
from .helpers import get_jwt_payload, get_jwt_raw
from .decorators import requires_jwt
from .errors import AuthError
