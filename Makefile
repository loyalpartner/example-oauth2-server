dev:
	AUTHLIB_INSECURE_TRANSPORT=1 FLASK_APP=app.py FLASK_ENV=development flask run --host=0.0.0.0

cert:
	@mkdir -p ./etc
	@hostname -i && \
		mkcert -cert-file ./etc/127.0.0.1.pem \
			-key-file ./etc/127.0.0.1-key.pem \
			127.0.0.1 \
			`hostname -i` \
			'example.com' \
			'*.example.com' \
			'www.exampleapis.com'

dev-https:
	AUTHLIB_INSECURE_TRANSPORT=1 python app.py
