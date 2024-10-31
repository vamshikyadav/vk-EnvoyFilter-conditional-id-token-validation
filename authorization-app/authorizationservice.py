from flask import Flask, request, jsonify
import jwt

app = Flask(__name__)

# Define allowed groups for authorization
ALLOWED_GROUPS = {"title1", "title2"}

# Secret or public key for JWT decoding
JWT_SECRET = "your-secret-key"  # Replace with actual key or JWKS for production

def verify_id_token(id_token):
    try:
        # Decode the JWT token
        decoded_token = jwt.decode(id_token, JWT_SECRET, algorithms=["HS256"])
        return decoded_token
    except jwt.InvalidTokenError:
        return None

@app.route("/authorize", methods=["POST"])
def authorize():
    # Get `id_token` from headers
    id_token = request.headers.get("id_token")
    if not id_token:
        return jsonify({"error": "id_token missing"}), 403

    decoded_token = verify_id_token(id_token)
    if not decoded_token:
        return jsonify({"error": "invalid token"}), 403

    # Check if any group in `ALLOWED_GROUPS` matches the `groups` claim in the token
    user_groups = set(decoded_token.get("groups", []))
    if ALLOWED_GROUPS.intersection(user_groups):
        return jsonify({"authorized": True}), 200
    else:
        return jsonify({"authorized": False}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
