def test_swagger_docs_accessible(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text.lower()

def test_openapi_security_scheme_configured(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    
    # Verify securitySchemes definition
    security_schemes = schema.get("components", {}).get("securitySchemes", {})
    assert "HTTPBearer" in security_schemes
    scheme = security_schemes["HTTPBearer"]
    assert scheme.get("type") == "http"
    assert scheme.get("scheme") == "bearer"
    assert scheme.get("bearerFormat") == "JWT"

    # Verify protected endpoints have security padlock attached
    paths = schema.get("paths", {})
    assert "security" in paths["/protected/profile"]["get"]
    assert "security" in paths["/protected/dashboard"]["get"]
    assert "security" in paths["/auth/logout"]["post"]

    # Verify public endpoints do not require authorization
    assert "security" not in paths["/public/info"]["get"] or paths["/public/info"]["get"]["security"] is None
    assert "security" not in paths["/auth/signup"]["post"] or paths["/auth/signup"]["post"]["security"] is None
    assert "security" not in paths["/auth/login"]["post"] or paths["/auth/login"]["post"]["security"] is None
