from argparse import ArgumentParser
from typing import Sequence, Callable, Any
from ._subcommand import SubcommandWrapper

__all__ = ["ArgumentParserBuilder"]


class ArgumentParserBuilder:
    __wrappers: list[SubcommandWrapper] = []

    def __init__(self, handler_name: str = "handler"):
        self.__handler_name = handler_name

    def subcommand(
        self, name: str, /, help: str | None = None, description: str | None = None
    ):
        def _wrapper(func: Callable[[ArgumentParser], Callable[[Any], Any]]):
            handle_wrapper = SubcommandWrapper(
                func, name, help=help, description=description
            )
            self.__wrappers.append(handle_wrapper)
            return handle_wrapper

        return _wrapper

    def __call__(self, args: Sequence[str] | None = None):
        parser = ArgumentParser()
        subparsers = parser.add_subparsers(dest="command", required=True)
        for wrapper in self.__wrappers:
            wrapper.register(self.__handler_name, subparsers)

        parsed = parser.parse_args(args)
        if self.__handler_name in parsed:
            parsed.__getattribute__(self.__handler_name)(parsed)
        else:
            parser.print_help()
