import pytest

from app.database import normalize_mongodb_uri


@pytest.mark.parametrize("value", [
    "mongodb+srv://user:password@cluster.example.mongodb.net/?retryWrites=true&w=majority",
    '  "mongodb+srv://user:password@cluster.example.mongodb.net/db"  ',
    "MONGODB_URI=mongodb://localhost:27017/secure_storage",
    " MONGODB_URI = 'mongodb://localhost:27017/secure_storage' ",
])
def test_mongodb_uri_normalizes_common_copy_formats(value):
    result = normalize_mongodb_uri(value)
    assert result.startswith(("mongodb://", "mongodb+srv://"))
    assert not result.startswith("MONGODB_URI=")


@pytest.mark.parametrize("value", [
    "cluster.example.mongodb.net",
    "mongodb+srv:/cluster.example.mongodb.net",
    "mongodb+srv://user name:password@cluster.example.mongodb.net",
])
def test_mongodb_uri_rejects_malformed_values_without_echoing_them(value):
    with pytest.raises(ValueError) as error:
        normalize_mongodb_uri(value)
    assert "MONGODB_URI" in str(error.value)
    assert value not in str(error.value)
