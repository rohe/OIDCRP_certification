#!/usr/bin/env python3
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
    _file = sys.argv[1]
    _test_desc = json.loads(open(_file).read())

    template_dir = os.path.join(dir_path, 'templates')
    _web_conf = json.loads(open("webserver_conf.json").read())

    context = create_context(dir_path, _web_conf)

    app = app_setup('oidc_rp')
    app.test_descr = _test_desc
    app.run(host=_web_conf["domain"], port=_web_conf["port"],
            debug=_web_conf.get("debug", False), ssl_context=context)
