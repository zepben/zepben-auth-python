__all__ = ["construct_url"]

from yurl import URL


def construct_url(
        protocol: str = None,
        host: str = "localhost",
        port: int = None,
        path: str = None
) -> str:
    return (URL(url=host) if URL(url=host).host else URL(host=host)) \
        .replace(scheme=protocol, port=port, path=path).as_string()
