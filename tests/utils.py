import flask


def create_test_app():
    app = flask.Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "secret"
    app.debug = True

    @app.route("/hello", methods=["GET", "POST", "DELETE"])
    def hello():
        return "hello"

    @app.route("/config")
    def config():
        return "config"

    @app.route("/restricted/endpoint")
    def restricted_endpoint():
        return "You are an Infraverantwoordelijke of an institution"

    @app.route("/anyof/endpoint")
    def anyof_endpoint():
        return "You passed the AnyOf test"

    @app.route("/customer/<customerId>")
    def check_customer_id(customerId):
        return "{} passed the test".format(customerId)

    @app.route("/cert_endpoint")
    def cert_endpoint():
        return "Only cert can call this"

    @app.errorhandler(401)
    def unauthorized(e):
        return flask.jsonify(error=401, detail=str(e)), 401

    @app.errorhandler(403)
    def forbidden(e):
        return flask.jsonify(error=403, detail=str(e)), 403

    onlyfor = flask.Blueprint("onlyfor", __name__, url_prefix="/onlyfor")

    @onlyfor.route("/klantsupport")
    def klantsupport():
        return "You are part of klantsupport"

    @onlyfor.route("/infrabeheerder")
    def infrabeheerder():
        return "You are an Infrabeheerder"

    app.register_blueprint(onlyfor)

    return app
