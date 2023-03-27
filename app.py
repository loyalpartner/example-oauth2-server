from website.app import create_app


app = create_app({
    'SECRET_KEY': 'secret',
    'OAUTH2_REFRESH_TOKEN_GENERATOR': True,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///db.sqlite',
})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, ssl_context=(
        "./etc/127.0.0.1.pem",
        "./etc/127.0.0.1-key.pem"
    ))
