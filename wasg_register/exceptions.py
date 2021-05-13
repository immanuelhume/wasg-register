class Exn(Exception):
    pass


class HTTPNotFoundExn(Exn):
    pass


class MalformedResponseExn(Exn):
    pass


class ServerErrorExn(Exn):
    pass
