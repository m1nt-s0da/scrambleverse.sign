from argparse import ArgumentParser, _SubParsersAction
from typing import Sequence, Callable, Any

__all__ = ["SubcommandWrapper"]


class SubcommandWrapper:
    def __init__(
        self,
        func: Callable[[ArgumentParser], Callable[[Any], Any]],
        name: str,
        *,
        help: str | None = None,
        description: str | None = None,
    ):
        self.__name = name
        self.__help = help
        self.__description = description
        self.__func = func

    def __call__(self, args: Sequence[str] | None = None):
        parser = ArgumentParser(
            # self.__name,
            description=self.__description
            or self.__help,
        )
        handler = self.__func(parser)
        parsed_args = parser.parse_args(args)
        handler(parsed_args)

    def register(
        self, handler_name: str, subparsers: "_SubParsersAction[ArgumentParser]"
    ):
        parser = subparsers.add_parser(
            self.__name,
            help=self.__help,
            description=self.__description or self.__help,
        )
        handler = self.__func(parser)
        parser.set_defaults(**{handler_name: handler})
