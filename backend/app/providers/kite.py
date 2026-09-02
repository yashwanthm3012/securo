from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Optional
from urllib.parse import urlencode

import httpx

from app.agents.services.crypto import decrypt, encrypt
from app.core.config import get_settings
from app.providers.base import (
    AccountData,
    AssetTransactionData,
    BankProvider,
    ConnectionData,
    HoldingData,
    SessionExpiredError,
    TransactionData,
)


class KiteProvider(BankProvider):
    """Zerodha Kite Connect provider."""

    BASE_URL = "https://api.kite.trade"
    LOGIN_URL = "https://kite.zerodha.com/connect/login?v=3"

    @property
    def name(self) -> str:
        return "kite"

    @property
    def flow_type(self) -> str:
        return "oauth"

    @property
    def redirect_uri(self) -> str:
        settings = get_settings()
        return (
            settings.kite_oauth_redirect_uri
            or super().redirect_uri
        )

    def _api_key(self) -> str:
        api_key = get_settings().kite_api_key

        if not api_key:
            raise RuntimeError("KITE_API_KEY is not configured")

        return api_key

    def _api_secret(self) -> str:
        secret = get_settings().kite_api_secret.get_secret_value()

        if not secret:
            raise RuntimeError("KITE_API_SECRET is not configured")

        return secret

    def _access_token(self, credentials: dict) -> str:
        encrypted = credentials.get("access_token_enc")

        if encrypted:
            token = decrypt(encrypted)

            if token:
                return token

        # Development/backward-compatibility fallback.
        token = credentials.get("access_token")

        if token:
            return token

        raise SessionExpiredError(
            "Kite access token is missing"
        )

    def _headers(self, access_token: str) -> dict[str, str]:
        return {
            "X-Kite-Version": "3",
            "Authorization": (
                f"token {self._api_key()}:{access_token}"
            ),
        }

    def _login_url(self, state: str) -> str:
        params = {
            "api_key": self._api_key(),
            "redirect_params": urlencode({
                "state": state,
            }),
        }

        return f"{self.LOGIN_URL}&{urlencode(params)}"

    async def get_oauth_url(
        self,
        redirect_uri: str,
        state: str,
        flow_params: Optional[dict] = None,
    ) -> str:
        return self._login_url(state)

    async def reauth_url(
        self,
        credentials: dict,
        settings: dict,
        redirect_uri: str,
        state: str,
    ) -> str:
        return self._login_url(state)

    async def handle_oauth_callback(
        self,
        code: str,
    ) -> ConnectionData:
        request_token = code.strip()

        if not request_token:
            raise ValueError(
                "Kite request_token is missing"
            )

        api_key = self._api_key()
        api_secret = self._api_secret()

        checksum = hashlib.sha256(
            f"{api_key}{request_token}{api_secret}".encode()
        ).hexdigest()

        async with httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=30,
        ) as client:
            response = await client.post(
                "/session/token",
                headers={
                    "X-Kite-Version": "3",
                },
                data={
                    "api_key": api_key,
                    "request_token": request_token,
                    "checksum": checksum,
                },
            )

        if response.status_code >= 400:
            raise RuntimeError(
                "Kite token exchange failed: "
                f"{response.status_code} {response.text}"
            )

        payload = response.json()

        if payload.get("status") != "success":
            raise RuntimeError(
                f"Kite token exchange failed: {payload}"
            )

        data = payload.get("data") or {}

        access_token = data.get("access_token")
        user_id = data.get("user_id")

        if not access_token:
            raise RuntimeError(
                "Kite response did not contain access_token"
            )

        if not user_id:
            raise RuntimeError(
                "Kite response did not contain user_id"
            )

        credentials = {
            "access_token_enc": encrypt(access_token),
            "user_id": user_id,
            "api_key": api_key,
        }

        account = AccountData(
            external_id=f"kite:{user_id}",
            name=f"Zerodha ({user_id})",
            type="investment",
            balance=Decimal("0"),
            currency="INR",
        )

        return ConnectionData(
            external_id=f"kite:{user_id}",
            institution_name="Zerodha",
            credentials=credentials,
            accounts=[account],
        )

    async def _request(
        self,
        path: str,
        credentials: dict,
    ) -> Any:
        access_token = self._access_token(credentials)

        async with httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=30,
        ) as client:
            response = await client.get(
                path,
                headers=self._headers(access_token),
            )

        if response.status_code in (401, 403):
            raise SessionExpiredError(
                "Kite access token expired. "
                "Reconnect Zerodha."
            )

        if response.status_code >= 400:
            raise RuntimeError(
                "Kite API request failed: "
                f"{response.status_code} {response.text}"
            )

        payload = response.json()

        if payload.get("status") != "success":
            raise RuntimeError(
                f"Kite API returned an error: {payload}"
            )

        return payload.get("data") or []

    async def get_accounts(
        self,
        credentials: dict,
    ) -> list[AccountData]:
        user_id = credentials.get("user_id") or "ZERODHA"

        return [
            AccountData(
                external_id=f"kite:{user_id}",
                name=f"Zerodha ({user_id})",
                type="investment",
                balance=Decimal("0"),
                currency="INR",
            )
        ]

    async def get_transactions(
        self,
        credentials: dict,
        account_external_id: str,
        since: Optional[date] = None,
        payee_source: str = "auto",
    ) -> list[TransactionData]:
        # Implemented in Phase 2.
        return []

    async def get_holdings(
        self,
        credentials: dict,
    ) -> list[HoldingData]:

        holdings = await self._request(
            "/portfolio/holdings",
            credentials,
        )

        result: list[HoldingData] = []

        for item in holdings:
            quantity = Decimal(
                str(item.get("quantity") or 0)
            )

            last_price = Decimal(
                str(item.get("last_price") or 0)
            )

            average_price = Decimal(
                str(item.get("average_price") or 0)
            )

            exchange = item.get("exchange") or ""
            instrument_token = item.get("instrument_token")
            symbol = item.get("tradingsymbol") or ""

            if instrument_token:
                external_id = (
                    f"kite:{exchange}:{instrument_token}"
                )
            else:
                external_id = (
                    f"kite:{exchange}:{symbol}"
                )

            result.append(
                HoldingData(
                    external_id=external_id,
                    name=symbol,
                    currency="INR",
                    current_value=quantity * last_price,
                    quantity=quantity,
                    unit_price=last_price,
                    purchase_price=quantity * average_price,
                    isin=item.get("isin"),
                    ticker=symbol,
                    metadata={
                        "exchange": exchange,
                        "instrument_token": instrument_token,
                        "product": item.get("product"),
                        "average_price": str(average_price),
                        "last_price": str(last_price),
                        "pnl": item.get("pnl"),
                        "day_change": item.get("day_change"),
                        "day_change_percentage": item.get(
                            "day_change_percentage"
                        ),
                        "close_price": item.get("close_price"),
                        "t1_quantity": item.get("t1_quantity"),
                        "used_quantity": item.get("used_quantity"),
                        "raw": item,
                    },
                    account_external_id=f"kite:{item.get('user_id')}" if item.get("user_id") else None,
                    account_name=None,
                )
            )

        return result

    async def get_asset_transactions(
        self,
        credentials: dict,
    ) -> list[AssetTransactionData]:
        """Fetch today's executed CNC equity trades from Kite.

        Kite's /trades endpoint contains executed trades for the current day.
        We intentionally restrict this integration to CNC equity trades because
        Securo is being used here as a long-term investment tracker.
        """

        trades = await self._request("/trades", credentials)

        result: list[AssetTransactionData] = []

        for item in trades:
            if not isinstance(item, dict):
                continue

            # Long-term equity delivery only.
            # Ignore MIS/NRML/etc. because this integration is for the user's
            # long-term investment portfolio.
            if str(item.get("product") or "").upper() != "CNC":
                continue

            transaction_type = str(
                item.get("transaction_type") or ""
            ).upper()

            if transaction_type not in {"BUY", "SELL"}:
                continue

            trade_id = item.get("trade_id")
            exchange = str(item.get("exchange") or "").upper()
            instrument_token = item.get("instrument_token")
            symbol = str(item.get("tradingsymbol") or "").strip()

            if not trade_id or not symbol:
                continue

            quantity_raw = item.get("quantity")
            price_raw = item.get("average_price")

            try:
                quantity = Decimal(str(quantity_raw))
                price = Decimal(str(price_raw))
            except (ValueError, TypeError, InvalidOperation):
                continue

            if quantity <= 0 or price < 0:
                continue

            # Must match the same external_id used by get_holdings().
            if instrument_token:
                asset_external_id = (
                    f"kite:{exchange}:{instrument_token}"
                )
            else:
                asset_external_id = (
                    f"kite:{exchange}:{symbol}"
                )

            timestamp_raw = (
                item.get("fill_timestamp")
                or item.get("exchange_timestamp")
            )

            trade_date: Optional[date] = None

            if timestamp_raw:
                try:
                    trade_date = datetime.strptime(
                        str(timestamp_raw),
                        "%Y-%m-%d %H:%M:%S",
                    ).date()
                except ValueError:
                    trade_date = None

            if trade_date is None:
                trade_date = date.today()

            result.append(
                AssetTransactionData(
                    external_id=f"kite:trade:{trade_id}",
                    asset_external_id=asset_external_id,
                    kind=(
                        "buy"
                        if transaction_type == "BUY"
                        else "sell"
                    ),
                    quantity=quantity,
                    price=price,
                    fee=Decimal("0"),
                    date=trade_date,
                    notes=(
                        f"Zerodha trade {trade_id} "
                        f"(order {item.get('order_id')})"
                    ),
                    metadata={
                        "trade_id": trade_id,
                        "order_id": item.get("order_id"),
                        "exchange_order_id": item.get(
                            "exchange_order_id"
                        ),
                        "exchange": exchange,
                        "tradingsymbol": symbol,
                        "instrument_token": instrument_token,
                        "product": item.get("product"),
                        "transaction_type": transaction_type,
                        "fill_timestamp": item.get(
                            "fill_timestamp"
                        ),
                        "exchange_timestamp": item.get(
                            "exchange_timestamp"
                        ),
                        "raw": item,
                    },
                )
            )

        return result

    async def refresh_credentials(self, credentials: dict) -> dict:
        """Kite access tokens cannot be refreshed through this integration.

        Kite access tokens normally expire, so when the token is no longer
        valid the user must reconnect Zerodha.
        """
        return credentials