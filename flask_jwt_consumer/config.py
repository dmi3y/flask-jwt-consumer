from flask import current_app

class _Config(object):
    """
    Helper object for accessing and verifying options in this extension.

    This is meant for internal use of the application; modifying config options
    should be done with flasks ```app.config```.
    Default values for the configuration options are set in the jwt_manager
    object. All of these values are read only.
    """

    @property
    def decode_keys(self):
        return self._public_keys

    @property
    def header_name(self):
        name = current_app.config['JWT_HEADER_NAME']
        if not name:
            raise RuntimeError('JWT_HEADER_NAME cannot be empty')
        return name

    @property
    def header_type(self):
        return current_app.config['JWT_HEADER_TYPE']

    @property
    def algorithm(self):
        return current_app.config['JWT_ALGORITHM']

    @property
    def audience(self):
        return current_app.config['JWT_IDENTITY']

    @property
    def _public_keys(self):
        keys = current_app.config['JWT_AUTHORIZED_KEYS']
        if not keys:
            raise RuntimeError('JWT_AUTHORIZED_KEYS must be set to use '
                               'asymmetric cryptography algorithm '
                               '"{}"'.format(self.algorithm))
        return bytes(keys, 'utf-8').splitlines()


config = _Config()
