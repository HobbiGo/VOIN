@pytest.mark.parametrize(
    "port",
    [
        -1,
        65536,
        True,
        "8080"
    ]
)
def test_invalid_port(api_integration, port):

    with pytest.raises(ValueError):
        VOINSecurityHTTPServer(
            api_integration,
            port=port
        )
