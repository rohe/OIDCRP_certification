#!/usr/bin/env python3
import argparse
import json
import os
import sys

from flask import Flask
from oidcrp.util import create_context

dir_path = os.path.dirname(os.path.realpath(__file__))


def app_setup(name=None):
    name = name or __name__
    app = Flask(name, static_url_path='')

    try:
        from .views import oidc_rp_views
    except ImportError:
        from views import oidc_rp_views

    app.register_blueprint(oidc_rp_views)

    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', dest="test_plan")
    parser.add_argument('-D', dest="domain")
    parser.add_argument('-P', dest="port")
    parser.add_argument('-i', dest="issuer")

    args = parser.parse_args()

    _test_plan = json.loads(open(args.test_plan).read())
    _test_plan["issuer"] = args.issuer
    _test_plan["domain"] = args.domain
    _test_plan["port"] = args.port
    _test_plan["base_url"] = "https://{}:{}".format(args.domain, args.port)

    _web_conf = json.loads(open("webserver_conf.json").read())
    _web_conf["port"] = args.port

    context = create_context(dir_path, _web_conf)

    app = app_setup('oidc_rp')
    app.test_plan = _test_plan
    app.run(host=_web_conf["domain"], port=_web_conf["port"],
            debug=_web_conf.get("debug", False), ssl_context=context)
