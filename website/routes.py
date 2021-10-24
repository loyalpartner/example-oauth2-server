import time
import random
import re
from urllib.parse import urlsplit, parse_qs
from flask import Blueprint, request, session, url_for
from flask import render_template, redirect, jsonify
from flask import make_response
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token
from authlib.oauth2 import OAuth2Error
from .models import db, User, OAuth2Client
from .oauth2 import authorization, require_oauth


bp = Blueprint('home', __name__)


def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None


def split_by_crlf(s):
    return [v for v in s.splitlines() if v]


@bp.route('/', methods=('GET', 'POST'))
def home():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            user.email = username + '@163.com'
            user.mobile = '1' + str(random.randint(0000000000, 9999999999))
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []

    return render_template('home.html', user=user, clients=clients)


@bp.route('/logout')
def logout():
    del session['id']
    return redirect('/')


@bp.route('/create_client', methods=('GET', 'POST'))
def create_client():
    user = current_user()
    if not user:
        return redirect('/')
    if request.method == 'GET':
        return render_template('create_client.html')

    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )

    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)

    db.session.add(client)
    db.session.commit()
    return redirect('/')


@bp.route('/edit_client/<client_id>', methods=('GET', 'POST'))
def edit_client(client_id):
    user = current_user()
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    if not user or not client:
        return redirect('/')
    if request.method == 'GET':
        print(client)
        return render_template('edit_client.html', client=client)

    form = request.form
    client_id = form["client_id"]
    # client_id_issued_at = int(time.time())
    client.client_id = client_id

    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)

    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = form['client_secret']

    db.session.commit()
    return redirect('/')


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return authorization.create_token_response()


@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    return authorization.create_endpoint_response('revocation')


@bp.route('/api/me')
@require_oauth('profile')
def api_me():
    user = current_token.user
    return jsonify(id=user.id, username=user.username)


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
def authorize():
    user = current_user()
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('website.routes.home', next=request.url))
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        return render_template('authorize.html', user=user, grant=grant)
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    grant_user = user
    return authorization.create_authorization_response(grant_user=grant_user)


@bp.route('/callback')
def callback():
    return ""

# 需要实现


@bp.route('/_/signin/challenge', methods=["POST"])
def challenge():
    user = None
    identifier = request.form['identifier']

    try:
        user = User.query.filter_by(email=identifier).first()
        grant = authorization.validate_consent_request(end_user=user)
    except OAuth2Error as error:
        return error.error
    response = authorization.create_authorization_response(grant_user=user)

    location = response.headers['location']
    query = parse_qs(urlsplit(location).query)

    response = jsonify(query['code'][0])

    response.set_cookie('oauth_code', value=query['code'][0])
    response.headers['google-accounts-signin'] = f'email="{user.email}", sessionindex=0, obfuscatedid="{user.id}"'
    return response

# 重定向到输入帐号界面


@bp.route('/embedded/setup/v2/chromeos')
def login():
    return redirect(f'/embedded/setup/v2/chromeos/identifier?{request.query_string.decode()}')

# 输入帐号界面


@bp.route('/embedded/setup/v2/chromeos/identifier')
def get_identifier():
    return render_template('identifier.html', clients=OAuth2Client.query.all())

# 处理帐号提交


@bp.route('/_/lookup/accountlookup', methods=["POST", "GET"])
def account_lookup():
    print(request.form)
    identifier = request.form['identifier']
    regex_email = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    regex_mobile = r'\d{11}'
    user = User()
    if re.fullmatch(regex_email, identifier):
        user = User.query.filter_by(email=identifier).first()
    elif re.fullmatch(regex_mobile, identifier):
        user = User.query.filter_by(mobile=identifier).first()

    return jsonify({'email': user.email, 'avatar': 'set avatar url'})


@bp.route('/oauth2/v2/tokeninfo', methods=['POST', 'GET'])
def token_info():
    print(request.headers)
    result = {
        "issued_to": "924641000710-rprso8onm0mlboicfn4sk86dp823jufm.apps.googleusercontent.com",
        "audience": "924641000710-rprso8onm0mlboicfn4sk86dp823jufm.apps.googleusercontent.com",
        "scope": "https://www.google.com/accounts/OAuthLogin",
        "expires_in": 3594,
        "access_type": "offline"
    }
    return jsonify(result)

# 需要实现


@bp.route('/oauth2/v1/userinfo', methods=['POST', 'GET'])
def userinfo():
    return jsonify({
        "id": "1",
        "email": "likai@gmail.com",
        "verified_email": True,
        "name": "李凯",
        "given_name": "凯",
        "family_name": "李",
        "picture": "https://lh3.googleusercontent.com/a/AATXAJzxDB-97N_IrXuADKjI165V6JNNmFKKdxmz-k-g=s96-c",
        "locale": "zh-CN"
    })

# 需要实现


@bp.route('/ListAccounts', methods=['POST'])
def list_accounts():
    print(request.cookies)
    print(request.headers)
    if len(request.cookies) > 0:
        result = ["gaia.l.a.r",
                  [
                      [
                          "gaia.l.a",
                          1,
                          "李凯",
                          "likai@163.com",
                          "https://lh3.googleusercontent.com/-trz8baMe1vA/AAAAAAAAAAI/AAAAAAAAAAA/j1_0SDVrzvw/s48-c/photo.jpg",
                          1,
                          1,
                          0,
                          None,
                          1,
                          "1",
                          None,
                          None,
                          None,
                          None,
                          1
                      ]
                  ]]
    else:
        result = ["gaia.l.a.r", []]
    return jsonify(result)

# 需要实现


@bp.route('/GetCheckConnectionInfo', methods=['GET', 'POST'])
def get_check_connection_info():
    # return jsonify([])
    return ""
