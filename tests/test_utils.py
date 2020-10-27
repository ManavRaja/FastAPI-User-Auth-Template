import motor
import pytest
from motor import motor_asyncio

from app import config
from app import utils


@pytest.mark.asyncio
async def test_get_settings():
    settings = utils.get_settings()
    assert settings == config.Settings()


@pytest.mark.asyncio
async def test_get_db():
    settings = utils.get_settings()
    assert await utils.get_db() == motor.motor_asyncio.AsyncIOMotorClient(settings.mongo_client_url)["Social-Media-Meme-API"]
