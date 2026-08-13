import asyncio
import hashlib
import logging
import time
from abc import ABC, abstractmethod

from click import launch
from rich.prompt import Prompt

from ..client import Client, DeezerClient, QobuzClient, SoundcloudClient, TidalClient
from ..config import Config
from ..console import console
from ..exceptions import AuthenticationError, MissingCredentialsError

logger = logging.getLogger("streamrip")


class CredentialPrompter(ABC):
    client: Client

    def __init__(self, config: Config, client: Client):
        self.config = config
        self.client = self.type_check_client(client)

    @abstractmethod
    def has_creds(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def prompt_and_login(self):
        """Prompt for credentials in the appropriate way,
        and save them to the configuration.
        """
        raise NotImplementedError

    @abstractmethod
    def save(self):
        """Save current config to file"""
        raise NotImplementedError

    @abstractmethod
    def type_check_client(self, client: Client):
        raise NotImplementedError


class QobuzPrompter(CredentialPrompter):
    client: QobuzClient

    def has_creds(self) -> bool:
        c = self.config.session.qobuz
        return c.email_or_userid != "" and c.password_or_token != ""

    async def prompt_and_login(self):
        if not self.has_creds():
            self._prompt_creds_and_set_session_config()

        while True:
            try:
                await self.client.login()
                break
            except AuthenticationError:
                console.print("[yellow]Invalid credentials, try again.")
                self._prompt_creds_and_set_session_config()
            except MissingCredentialsError:
                self._prompt_creds_and_set_session_config()

    def _prompt_creds_and_set_session_config(self):
        email = Prompt.ask("Enter your Qobuz email")
        pwd_input = Prompt.ask("Enter your Qobuz password (invisible)", password=True)

        pwd = hashlib.md5(pwd_input.encode("utf-8")).hexdigest()
        console.print(
            f"[green]Credentials saved to config file at [bold cyan]{self.config.path}",
        )
        c = self.config.session.qobuz
        c.use_auth_token = False
        c.email_or_userid = email
        c.password_or_token = pwd

    def save(self):
        c = self.config.session.qobuz
        cf = self.config.file.qobuz
        cf.use_auth_token = False
        cf.email_or_userid = c.email_or_userid
        cf.password_or_token = c.password_or_token
        self.config.file.set_modified()

    def type_check_client(self, client) -> QobuzClient:
        assert isinstance(client, QobuzClient)
        return client


class TidalPrompter(CredentialPrompter):
    # Overall time to allow for login; None waits indefinitely (Ctrl-C to give
    # up). Tidal expires the device code itself after ~5 minutes, so waiting
    # longer than one code's lifetime means issuing a *fresh* code and link
    # rather than polling a dead one -- the previous fixed 10 minute wait spent
    # its second half polling an already-expired code and then failed with a
    # bare exception.
    timeout_s: int | None = 600
    client: TidalClient

    def has_creds(self) -> bool:
        return len(self.config.session.tidal.access_token) > 0

    def _timed_out(self, start: float) -> bool:
        return self.timeout_s is not None and time.time() - start > self.timeout_s

    async def prompt_and_login(self):
        start = time.time()
        info: dict | None = None

        while info is None:
            device_code, uri, expires_in = await self.client._get_device_code()
            login_link = f"https://{uri}"
            console.print(
                f"Go to [blue underline]{login_link}[/blue underline] to log into Tidal.",
            )
            if self.timeout_s is None:
                console.print(
                    "[dim]Waiting for you to authorize -- press Ctrl-C to cancel.",
                )
            launch(login_link)

            # Stop polling shortly before Tidal expires this code, so we loop
            # around and print a fresh link instead of a confusing failure.
            code_deadline = time.time() + max(expires_in - 10, 10)
            while time.time() < code_deadline:
                if self._timed_out(start):
                    raise AuthenticationError("Timed out waiting for Tidal login.")
                status, resp = await self.client._get_auth_status(device_code)
                if status == 0:
                    info = resp
                    break
                if status != 2:
                    raise AuthenticationError(
                        "Tidal login failed -- the request may have been denied.",
                    )
                await asyncio.sleep(4)

            if info is None:
                if self._timed_out(start):
                    raise AuthenticationError("Timed out waiting for Tidal login.")
                console.print("[yellow]That link expired. Getting a new one...")

        c = self.config.session.tidal
        c.user_id = info["user_id"]  # type: ignore
        c.country_code = info["country_code"]  # type: ignore
        c.access_token = info["access_token"]  # type: ignore
        c.refresh_token = info["refresh_token"]  # type: ignore
        c.token_expiry = info["token_expiry"]  # type: ignore

        self.client._update_authorization_from_config()
        self.client.logged_in = True
        self.save()

    def type_check_client(self, client) -> TidalClient:
        assert isinstance(client, TidalClient)
        return client

    def save(self):
        c = self.config.session.tidal
        cf = self.config.file.tidal
        cf.user_id = c.user_id
        cf.country_code = c.country_code
        cf.access_token = c.access_token
        cf.refresh_token = c.refresh_token
        cf.token_expiry = c.token_expiry
        self.config.file.set_modified()


class DeezerPrompter(CredentialPrompter):
    client: DeezerClient

    def has_creds(self):
        c = self.config.session.deezer
        return c.arl != ""

    async def prompt_and_login(self):
        if not self.has_creds():
            self._prompt_creds_and_set_session_config()
        while True:
            try:
                await self.client.login()
                break
            except AuthenticationError:
                console.print("[yellow]Invalid arl, try again.")
                self._prompt_creds_and_set_session_config()
        self.save()

    def _prompt_creds_and_set_session_config(self):
        console.print(
            "If you're not sure how to find the ARL cookie, see the instructions at ",
            "[blue underline]https://github.com/nathom/streamrip/wiki/Finding-your-Deezer-ARL-Cookie",
        )
        c = self.config.session.deezer
        c.arl = Prompt.ask("Enter your [bold]ARL")

    def save(self):
        c = self.config.session.deezer
        cf = self.config.file.deezer
        cf.arl = c.arl
        self.config.file.set_modified()
        console.print(
            f"[green]Credentials saved to config file at [bold cyan]{self.config.path}",
        )

    def type_check_client(self, client) -> DeezerClient:
        assert isinstance(client, DeezerClient)
        return client


class SoundcloudPrompter(CredentialPrompter):
    def has_creds(self) -> bool:
        return True

    async def prompt_and_login(self):
        pass

    def save(self):
        pass

    def type_check_client(self, client) -> SoundcloudClient:
        assert isinstance(client, SoundcloudClient)
        return client


PROMPTERS = {
    "qobuz": QobuzPrompter,
    "deezer": DeezerPrompter,
    "tidal": TidalPrompter,
    "soundcloud": SoundcloudPrompter,
}


def get_prompter(client: Client, config: Config) -> CredentialPrompter:
    """Return an instance of a prompter."""
    p = PROMPTERS[client.source]
    return p(config, client)
