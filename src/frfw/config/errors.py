class ConfigError(Exception):
    """Raised when a configuration file fails schema validation.

    The message is written to be shown directly to a human (CLI user or,
    later, webUI form), so it should name the offending field/value.
    """
