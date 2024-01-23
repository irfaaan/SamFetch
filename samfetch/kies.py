__all__ = [
    "KiesDict",
    "KiesData",
    "KiesConstants",
    "KiesRequest",
    "KiesUtils",
    "KiesFirmwareList"
]


from collections import UserDict
from typing import List, Tuple, Dict, Any, Optional
import dicttoxml
import xmltodict
import re
import httpx
import string
from samfetch.session import Session
from .imei import generate_random_imei



class IMEIGenerator:
        @staticmethod
        def generate_random_imei(tac: str) -> str:
            """Generate a random IMEI based on the provided TAC."""
            random_imei = generate_random_imei(tac)
            return random_imei


class KiesFirmwareList:
    """
    Parses firmware list.
    """
    def __init__(self, data : Dict) -> None:
        self._data = data
        self._versions = None if ("versioninfo" not in self._data) else self._data["versioninfo"]["firmware"]["version"]

    @classmethod
    def from_xml(cls, xml : str) -> "KiesFirmwareList":
        return cls(xmltodict.parse(xml, dict_constructor=dict))

    @property
    def exists(self) -> bool:
        if (self._versions == None) or (self.latest == None):
            return False
        return True

    @property
    def latest(self) -> Optional[str]:
        if "latest" not in self._versions:
            return None
        elif isinstance(self._versions["latest"], str):
            return KiesUtils.parse_firmware(self._versions["latest"])
        elif isinstance(self._versions["latest"], dict):
            return KiesUtils.parse_firmware(self._versions["latest"]["#text"])
        return None

    @property
    def alternate(self) -> List[str]:
        upgrade = self._versions["upgrade"]["value"]
        if upgrade == None:
            return []
        elif isinstance(upgrade, list):
            return [KiesUtils.parse_firmware(x["#text"]) for x in upgrade if x["#text"].count("/") > 1]
        elif isinstance(upgrade, dict):
            return [KiesUtils.parse_firmware(upgrade["#text"])] if upgrade["#text"].count("/") > 1 else []
        return []

class KiesDict(UserDict):
    """
    A dictionary object for reading values in KiesData.
    """
    def __getitem__(self, key) -> Any:
        d = super().__getitem__(key)
        if type(d) is not dict:
            return d
        else:
            return d.get("Data", d)

    def get_first(self, *keys) -> Any:
        for key in keys:
            d = self.get(key, None)
            if d != None:
                return d

class KiesData:
    """
    A class that holds Kies server responses.
    """
    def __init__(self, data : Dict) -> None:
        self._data = data

    @classmethod
    def from_xml(cls, xml : str) -> "KiesData":
        return cls(xmltodict.parse(xml, dict_constructor=dict))

    @property
    def body(self) -> "KiesDict":
        return KiesDict(self._data["FUSMsg"]["FUSBody"].get("Put", {}))

    @property
    def results(self) -> "KiesDict":
        return KiesDict(self._data["FUSMsg"]["FUSBody"]["Results"])

    @property
    def status_code(self) -> int:
        return int(self._data["FUSMsg"]["FUSBody"]["Results"]["Status"])

    @property
    def session_id(self) -> str:
        return self._data["FUSMsg"]["FUSHdr"]["SessionID"]

class KiesConstants:
    """
    Constants for Kies server interactions.
    """
    GET_FIRMWARE_URL = "http://fota-cloud-dn.ospserver.net/firmware/{0}/{1}/version.xml"
    NONCE_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadGenerateNonce.do"
    BINARY_INFO_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInform.do"
    BINARY_FILE_URL = "https://neofussvr.sslcs.cdngc.net/NF_DownloadBinaryInitForMass.do"
    BINARY_DOWNLOAD_URL = "http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do"

    HEADERS = lambda nonce=None, signature=None: \
        {
            "Authorization": f'FUS nonce="{nonce or ""}", signature="{signature or ""}", nc="", type="", realm="", newauth="1"',
            "User-Agent": "Kies2.0_FUS"
        }

    COOKIES = lambda session_id=None: \
        {
            "JSESSIONID": session_id or ""
        }

    client_version = "4.3.23123_1"
    #imei = "35439911"

    BINARY_INFO = lambda firmware_version, region, model, imei, logic_check: \
        dicttoxml.dicttoxml({
            "FUSMsg": {
                "FUSHdr": {"ProtoVer": "1.0"},
                "FUSBody": {
                    "Put": {
                        "ACCESS_MODE": {"Data": "2"},
                        "BINARY_NATURE": {"Data": "1"},
                        "CLIENT_PRODUCT": {"Data": "Smart Switch"},
                        "DEVICE_FW_VERSION": {"Data": firmware_version},
                        "DEVICE_LOCAL_CODE": {"Data": region},
                        "DEVICE_MODEL_NAME": {"Data": model},
                        "DEVICE_IMEI_PUSH": {"Data": imei},
                        "CLIENT_VERSION": {"Data": KiesConstants.client_version},
                        "LOGIC_CHECK": {"Data": logic_check}
                    }
                }
            }
        }, attr_type=False, root=False)

    BINARY_FILE = lambda filename, logic_check: \
        dicttoxml.dicttoxml({
            "FUSMsg": {
                "FUSHdr": {"ProtoVer": "1.0"},
                "FUSBody": {
                    "Put": {
                        "BINARY_FILE_NAME": {"Data": filename},
                        "LOGIC_CHECK": {"Data": logic_check},
#                         "DEVICE_IMEI_PUSH": {"Data": imei},
#                         "CLIENT_VERSION": {"Data": KiesConstants.client_version}
                    }
                }
            }
        }, attr_type=False, root=False)


class KiesRequest:
    """
    Builds prebuilt requests for getting data from Kies servers.
    """
    @staticmethod
    def get_nonce() -> httpx.Request:
        return httpx.Request(
            "POST",
            KiesConstants.NONCE_URL,
            headers=KiesConstants.HEADERS()
        )

    @staticmethod
    def list_firmware(region: str, model: str) -> httpx.Request:
        return httpx.Request(
            "GET",
            KiesConstants.GET_FIRMWARE_URL.format(region, model)
        )



    @staticmethod
    def get_binary(region: str, model: str, firmware: str, imei: str, session: Session) -> httpx.Request:
        binary_info = KiesConstants.BINARY_INFO(
            firmware, region, model, imei, session.logic_check(firmware)
        )
        return httpx.Request(
            "POST",
            KiesConstants.BINARY_INFO_URL,
            content=binary_info,
            headers=KiesConstants.HEADERS(session.encrypted_nonce, session.auth),
            cookies=KiesConstants.COOKIES(session.session_id)
        )

    @staticmethod
    def get_download(path: str, session: Session) -> httpx.Request:
        filename = path.split("/")[-1]
        return httpx.Request(
            "POST",
            KiesConstants.BINARY_FILE_URL,
            content=KiesConstants.BINARY_FILE(
                filename, session.logic_check(filename.split(".")[0][-16:])
            ),
            headers=KiesConstants.HEADERS(
                session.encrypted_nonce, session.auth
            ),
            cookies=KiesConstants.COOKIES(session.session_id),
#             params={"client_version": client_version}
        )

    @staticmethod
    def start_download(path: str, session: Session, custom_range: str = None) -> httpx.Request:
        headers = KiesConstants.HEADERS(session.encrypted_nonce, session.auth)
        if custom_range:
            headers["Range"] = custom_range
        return httpx.Request(
            "GET",
            KiesConstants.BINARY_DOWNLOAD_URL + "?file=" + path,
            headers=headers,
            cookies=KiesConstants.COOKIES(session.session_id)
        )

class KiesUtils:
    """
    Utility functions for Kies server interactions.
    """
    @staticmethod
    def parse_firmware(firmware: str) -> str:
        if firmware:
            l = firmware.split("/")
            if len(l) == 3:
                l.append(l[0])
            if l[2] == "":
                l[2] = l[0]
            return "/".join(l)
        raise ValueError("Invalid firmware format.")

    @staticmethod
    def parse_range_header(header: str) -> Tuple[int, int]:
        ran = header.strip().removeprefix("bytes=").split("-", maxsplit=1)
        if len(ran) != 2:
            return -1, -1
        return int(ran[0] or 0), int(ran[1] or 0)

    @staticmethod
    def join_path(*args, prefix="/") -> str:
        paths = []
        for p in args:
            if p:
                paths.append(p.strip().replace("/", " ").replace("\\", " ").strip().replace(" ", "/"))
        return (prefix or "") + "/".join(paths)

    @staticmethod
    def read_firmware(firmware: str) -> Tuple[Optional[str], Optional[int], int, int, int]:
        if firmware.count("/") == 3:
            pda = firmware.split("/")[0][-6:]
            result = [None, None, None, None, None]
            if (pda[0] in ["U", "S"]):
                result[0] = pda[0:2]
                result[1] = ord(pda[2]) - ord("A")
                result[2] = (ord(pda[3]) - ord("R")) + 2018
                result[3] = ord(pda[4]) - ord("A")
                result[4] = (string.digits + string.ascii_uppercase).index(pda[5])
            else:
                result[2] = (ord(pda[-3]) - ord("R")) + 2018
                result[3] = ord(pda[-2]) - ord("A")
                result[4] = (string.digits + string.ascii_uppercase).index(pda[-1])
            return result
        raise ValueError("Invalid firmware format.")

    @staticmethod
    def read_firmware_dict(firmware: str) -> dict:
        ff = KiesUtils.read_firmware(firmware)
        return {
            "bl": ff[0],
            "date": f"{ff[2]}.{ff[3]}",
            "it": f"{ff[1]}.{ff[4]}",
        }