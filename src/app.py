from typing import Union
from collections.abc import Iterator
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params, OnPollParams
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset, AssetField
from .common import logger
from soar_sdk.exceptions import ActionFailure
from soar_sdk.models.container import Container
from soar_sdk.models.artifact import Artifact
import requests


class Asset(BaseAsset):
    api_id: str = AssetField(required=True, description="API ID")
    secret: str = AssetField(required=True, description="Secret")


app = App(
    name="censys",
    app_type="information",
    logo="logo_censys.svg",
    logo_dark="logo_censys_dark.svg",
    product_vendor="Censys, Inc.",
    product_name="Censys",
    publisher="Splunk",
    appid="97c8df6f-c870-4482-b6ca-b6c31745fbab",
    fips_compliant=True,
    asset_cls=Asset,
)

CENSYS_BASE_URL = "https://search.censys.io"
CENSYS_TEST_ENDPOINT = "/api/v1/account"
@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Test connectivity by retrieving a valid token"""

    logger.info("In action handler for: test_connectivity")
    url = CENSYS_BASE_URL+CENSYS_TEST_ENDPOINT
    try:
        response = requests.get(url, auth =(asset.api_id,asset.secret), headers={"Accept": "application/json"})
        response.raise_for_status()
    except Exception as e:
        raise ActionFailure(
                    f"Request failed for {url}. Details: {e}"
                ) from e

    logger.info("Test connectivity passed!")