import json
import logging
import os
import re
from urllib.parse import parse_qs

from cryptojwt import KeyJar
from cryptojwt.key_jar import init_key_jar
from flask import Blueprint
from flask import current_app
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask.helpers import make_response
from flask.helpers import send_from_directory
from oidcrp import rp_handler
from oidcrp.configure import Configuration
from oidcrp.configure import RPConfiguration
from oidcrp.exception import OidcServiceError
from oidcrp.rp_handler import RPHandler
import werkzeug

logger = logging.getLogger(__name__)

dir_path = os.path.dirname(os.path.realpath(__file__))

oidc_rp_views = Blueprint('oidc_rp', __name__, url_prefix='')


def compact(qsdict):
    res = {}
    for key, val in qsdict.items():
        if len(val) == 1:
            res[key] = val[0]
        else:
            res[key] = val
    return res


def init_oidc_rp_handler(rp_config):
    if rp_config.keys:
        _kj = init_key_jar(**rp_config.keys)
        _path = rp_config.keys['public_path']
        # removes ./ and / from the begin of the string
        _path = re.sub('^(.)/', '', _path)
    else:
        _kj = KeyJar()
        _path = ''
    _kj.httpc_params = rp_config.httpc_params

    rph = RPHandler(rp_config.base_url, rp_config.clients, services=rp_config.services,
                    hash_seed=rp_config.hash_seed, keyjar=_kj, jwks_path=_path,
                    httpc_params=rp_config.httpc_params)

    return rph


@oidc_rp_views.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)


@oidc_rp_views.route('/')
def index():
    _tests = list(current_app.test_plan["test"].keys())
    return render_template('test_choice.html', tests=_tests,
                           base_url=current_app.test_plan["base_url"])


def test_sequence():
    step = current_app.info["step"]
    test_id = current_app.info["test_id"]
    _desc = current_app.test_plan["test"][test_id]
    # Now for the test sequence
    for spec in _desc["sequence"][step:]:
        current_app.info["step"] += 1
        _func = getattr(current_app.rph, spec["method"])
        _kwargs = {k: current_app.info[v] for k, v in spec.get("args", {}).items()}

        try:
            _res = _func(**_kwargs)
        except OidcServiceError as err:
            logger.error(f"{err}")
            _res = None

        if _res and "return" in spec:
            current_app.info[spec["return"]] = _res

        if spec["method"] == "begin":
            if "client" not in current_app.info:
                logger.debug("issuers: {}".format(list(current_app.rph.issuer2rp.keys())))
                current_app.info["client"] = current_app.rph.issuer2rp[current_app.info["issuer"]]
            response = redirect(_res['url'], 303)
            return response
        elif spec["method"] == 'init_authorization':
            response = redirect(_res['url'], 303)
            return response

    # back to start page
    return index()


@oidc_rp_views.route('/test')
def test():
    test_id = request.args['test_id']

    current_app.desc = current_app.test_plan["test"][test_id]
    if "config" in current_app.desc:
        conf = current_app.desc["config"]
    else:
        conf = current_app.test_plan["default_config"]

    issuer = current_app.test_plan["issuer"]
    # template_dir = os.path.join(dir_path, 'templates')

    _str = open(conf).read()
    _cnf = json.loads(_str)
    _cnf['logging']["handlers"]["file"]["filename"] = f"{test_id}.log"
    _cnf["domain"] = current_app.test_plan["domain"]
    _cnf["port"] = current_app.test_plan["port"]
    _cnf["base_url"] = current_app.test_plan["base_url"]
    _config = Configuration(_cnf, entity_conf=[{"class": RPConfiguration, "attr": "rp"}])

    current_app.rph = init_oidc_rp_handler(_config.rp)
    current_app.info = {"step": 0, "test_id": test_id}

    for key, val in current_app.test_plan.items():
        if key == "test":
            continue
        current_app.info[key] = val

    return test_sequence()


def get_rp(op_identifier):
    try:
        _iss = current_app.rph.hash2issuer[op_identifier]
    except KeyError:
        try:
            rp = current_app.rph.issuer2rp[op_identifier]
        except KeyError:
            logger.error('Unkown issuer: {} not among {}'.format(
                op_identifier, list(current_app.rph.hash2issuer.keys())))
            return make_response(f"Unknown OP identifier: {op_identifier}", 400)
    else:
        try:
            rp = current_app.rph.issuer2rp[_iss]
        except KeyError:
            return make_response(f"Couldn't find client for issuer: '{_iss}'", 400)

    return rp


def after_authn(request_args):
    logger.debug(f"{request_args}")
    rp = current_app.info["client"]

    if hasattr(rp, 'status_code') and rp.status_code != 200:
        logger.error(rp.response[0].decode())
        return rp.response[0], rp.status_code

    # ease access
    current_app.info['state'] = request_args.get('state')
    current_app.info["response"] = request_args
    return test_sequence()


# def get_op_identifier_by_cb_uri(url: str):
#     uri = urljoin(url, urlparse(url).path)
#     for k, v in current_app.rph.issuer2rp.items():
#         _cntx = v.get_service_context()
#         for endpoint in ("redirect_uris",
#                          "post_logout_redirect_uris",
#                          "frontchannel_logout_uri",
#                          "backchannel_logout_uri"):
#             if uri in _cntx.get(endpoint, []):
#                 return k


@oidc_rp_views.route('/authz_cb/<op_identifier>')
def authz_cb(op_identifier):
    return after_authn(request.args)


@oidc_rp_views.errorhandler(werkzeug.exceptions.BadRequest)
def handle_bad_request(e):
    return 'bad request!', 400


@oidc_rp_views.route('/repost_fragment')
def repost_fragment():
    args = compact(parse_qs(request.args['url_fragment']))
    return after_authn(args)


@oidc_rp_views.route('/ihf_cb')
def ihf_cb(self, op_identifier='', **kwargs):
    logger.debug('implicit_hybrid_flow kwargs: {}'.format(kwargs))
    return render_template('repost_fragment.html')


@oidc_rp_views.route('/session_iframe')
def session_iframe():  # session management
    logger.debug('session_iframe request_args: {}'.format(request.args))

    _rp = get_rp(session['op_identifier'])
    _context = _rp.client_get("service_context")
    session_change_url = "{}/session_change".format(_context.base_url)

    _issuer = current_app.rph.hash2issuer[session['op_identifier']]
    args = {
        'client_id': session['client_id'],
        'session_state': session['session_state'],
        'issuer': _issuer,
        'session_change_url': session_change_url
    }
    logger.debug('rp_iframe args: {}'.format(args))
    _template = _context.add_on["status_check"]["session_iframe_template_file"]
    return render_template(_template, **args)


@oidc_rp_views.route('/session_change')
def session_change():
    logger.debug('session_change: {}'.format(session['op_identifier']))
    _rp = get_rp(session['op_identifier'])

    # If there is an ID token send it along as a id_token_hint
    _aserv = _rp.client_get("service", 'authorization')
    request_args = {"prompt": "none"}

    request_args = _aserv.multiple_extend_request_args(
        request_args, session['state'], ['id_token'],
        ['auth_response', 'token_response', 'refresh_token_response'])

    logger.debug('session_change:request_args {}'.format(request_args))

    _info = current_app.rph.init_authorization(_rp, request_args=request_args)
    logger.debug('session_change:authorization request: {}'.format(_info['url']))
    return redirect(_info['url'], 303)


# post_logout_redirect_uri
@oidc_rp_views.route('/session_logout/<op_identifier>')
def session_logout(op_identifier):
    # op_identifier = get_op_identifier_by_cb_uri(request.url)
    # _rp = get_rp(op_identifier)
    _rp = current_app.info["client"]
    logger.debug('post_logout')
    return "Post logout from {}".format(_rp.client_get("service_context").issuer)


# RP initiated logout
@oidc_rp_views.route('/logout')
def logout():
    logger.debug('logout')
    _info = current_app.rph.logout(state=session['state'])
    logger.debug('logout redirect to "{}"'.format(_info['url']))
    return redirect(_info['url'], 303)


@oidc_rp_views.route('/bc_logout/<op_identifier>', methods=['GET', 'POST'])
def backchannel_logout(op_identifier):
    _rp = get_rp(op_identifier)
    try:
        _state = rp_handler.backchannel_logout(_rp, request.data)
    except Exception as err:
        logger.error('Exception: {}'.format(err))
        return 'System error!', 400
    else:
        _rp.session_interface.remove_state(_state)
        return "OK"


@oidc_rp_views.route('/fc_logout/<op_identifier>', methods=['GET', 'POST'])
def frontchannel_logout(op_identifier):
    _rp = get_rp(op_identifier)
    sid = request.args['sid']
    _iss = request.args['iss']
    if _iss != _rp.client_get("service_context").get('issuer'):
        return 'Bad request', 400
    _state = _rp.session_interface.get_state_by_sid(sid)
    _rp.session_interface.remove_state(_state)
    return "OK"
