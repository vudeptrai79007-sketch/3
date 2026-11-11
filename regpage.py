import os
import re
import sys
import json
import time
import uuid
import hmac
import base64
import struct
import random
import hashlib
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Khóa đồng bộ khi chạy đa luồng
print_lock = threading.Lock()
file_lock = threading.Lock()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SUCCESS_FILE = os.path.join(BASE_DIR, "success_pages.txt")
FAILED_FILE = os.path.join(BASE_DIR, "failed_accounts.txt")
ACCOUNTS_FILE = os.path.join(BASE_DIR, "accounts.txt")


def safe_print(msg: str):
    with print_lock:
        print(msg)


def save_line(filepath: str, content: str):
    with file_lock:
        with open(filepath, "a", encoding="utf-8") as f:
            f.write(content.strip() + "\n")


def decode_unicode_text(text: str) -> str:
    """Giải mã toàn bộ chuỗi \\uXXXX bị lồng nhiều lớp trong Bloks sang tiếng Việt có dấu"""
    if not text:
        return ""
    decoded = re.sub(r'\\+u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    return decoded.replace('\\"', '"').replace("\\'", "'").replace("\\\\", "").strip("\\")


class FacebookAllInOne:
    def __init__(self, proxy: str = None):
        self.session = requests.Session()
        if proxy and proxy.strip():
            proxy = proxy.strip().strip('"').strip("'")
            # Hỗ trợ định dạng ip:port:user:pass hoặc user:pass@ip:port
            if not proxy.startswith("http"):
                parts = proxy.split(":")
                if len(parts) == 4 and "@" not in proxy:
                    proxy = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                else:
                    proxy = f"http://{proxy}"
            self.session.proxies = {"http": proxy, "https": proxy}

        self.fb4a_app_id = "350685531728"
        self.fb4a_client_token = "62f8ce9f74b12f84c123cc23437a4a32"
        self.access_token = None
        self.cookie = None
        self.uid = "Unknown"

        self.user_agent = (
            "[FBAN/FB4A;FBAV/537.0.0.47.77;FBBV/546221452;"
            "FBDM/{density=2.0,width=720,height=1440};FBLC/vi_VN;"
            "FBRV/0;FBCR/Viettel;FBMF/samsung;FBBD/samsung;"
            "FBPN/com.facebook.katana;FBDV/SM-G975F;FBSV/12;FBOP/1;FBCA/arm64-v8a:;]"
        )

    @staticmethod
    def random_page_name() -> str:
        ho = ["Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Huỳnh", "Phan", "Vũ", "Võ", "Đặng", "Bùi", "Đỗ", "Hồ", "Ngô", "Dương", "Lý"]
        dem = ["Văn", "Thị", "Minh", "Hoàng", "Ngọc", "Thanh", "Quốc", "Gia", "Bảo", "Đức", "Phương", "Anh", "Tuấn", "Hải"]
        ten = ["Anh", "Bình", "Châu", "Dũng", "Giang", "Hà", "Hải", "Hiếu", "Hòa", "Hùng", "Hương", "Huyền", "Khánh", "Khoa", "Linh", "Long", "Mai", "Minh", "My", "Nam", "Ngọc", "Nhung", "Phúc", "Phương", "Quân", "Quang", "Quỳnh", "Sơn", "Tâm", "Thảo", "Thắng", "Thành", "Thịnh", "Thu", "Trang", "Trung", "Tú", "Tuấn", "Tùng", "Uyên", "Việt", "Vinh", "Vy", "Yến"]
        suffix = ["Official", "Vlog", "Blog", "Store", "Shop", "Media", "Daily", "News", "24h", "TV", "Channel", "Studio"]

        if random.choice([True, False]):
            return f"{random.choice(ho)} {random.choice(dem)} {random.choice(ten)}"
        return f"{random.choice(ho)} {random.choice(ten)} {random.choice(suffix)}"

    @staticmethod
    def get_totp_2fa(secret_key: str) -> str:
        """Giải mã 6 số 2FA từ Secret Key"""
        clean_key = secret_key.replace(" ", "").strip().upper()
        padding = len(clean_key) % 8
        if padding != 0:
            clean_key += "=" * (8 - padding)
        key = base64.b32decode(clean_key, casefold=True)
        intervals_no = int(time.time()) // 30
        msg = struct.pack(">Q", intervals_no)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
        return f"{code:06d}"

    @staticmethod
    def _parse_session_cookies(cookies_list: list) -> str:
        return "; ".join([f"{c['name']}={c['value']}" for c in cookies_list if "name" in c and "value" in c])

    # =========================================================================
    # 1. CHUYỂN ĐỔI MỌI LOẠI TOKEN SANG EAAAAU (APP ANDROID KATANA)
    # =========================================================================
    def convert_token_to_eaaau(self, token: str) -> str:
        token = token.strip()
        if token.startswith("EAAAAU") or token.startswith("EAAAAAY"):
            return token
        try:
            res = self.session.get(
                "https://api.facebook.com/method/auth.getSessionforApp",
                params={
                    "access_token": token,
                    "format": "json",
                    "new_app_id": self.fb4a_app_id,
                    "generate_session_cookies": "1"
                },
                headers={"User-Agent": self.user_agent},
                timeout=20
            ).json()
            if "access_token" in res:
                return res["access_token"]
        except Exception:
            pass
        return token

    # =========================================================================
    # 2. LẤY TOKEN TỪ COOKIE (TÍCH HỢP 3 CỔNG DỰ PHÒNG)
    # =========================================================================
    def login_with_cookie(self, cookie: str):
        self.cookie = cookie.strip()
        web_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Cookie": self.cookie,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate"
        }

        try:
            base_token = None

            # Cổng 1: Lấy EAAG từ Business Locations
            res1 = self.session.get("https://business.facebook.com/business_locations", headers=web_headers, timeout=20)
            match1 = re.search(r'(EAAG\w+)', res1.text)
            if match1:
                base_token = match1.group(1)

            # Cổng 2: Lấy EAAB / EAAA từ Ads Manager
            if not base_token:
                res2 = self.session.get("https://adsmanager.facebook.com/adsmanager/manage/campaigns", headers=web_headers, timeout=20)
                match2 = re.search(r'(EAA[a-zA-Z0-9]{50,})', res2.text)
                if match2:
                    base_token = match2.group(1)
                else:
                    act_match = re.search(r'act=(\d+)', res2.text) or re.search(r'act=(\d+)', res2.url)
                    if act_match:
                        url_act = f"https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={act_match.group(1)}"
                        res_act = self.session.get(url_act, headers=web_headers, timeout=20)
                        match_eaa = re.search(r'(EAA[a-zA-Z0-9]{50,})', res_act.text)
                        if match_eaa:
                            base_token = match_eaa.group(1)

            # Cổng 3: Lấy EAAA từ Composer Ocelot
            if not base_token:
                res3 = self.session.get("https://www.facebook.com/composer/ocelot/async_loader/?publisher=feed", headers=web_headers, timeout=20)
                match3 = re.search(r'(EAA[a-zA-Z0-9]{50,})', res3.text)
                if match3:
                    base_token = match3.group(1)

            if not base_token:
                return False, "Cookie Die hoặc không trích xuất được Token từ Cookie!"

            # Đổi Token trung gian sang EAAAAU của Android
            self.access_token = self.convert_token_to_eaaau(base_token)
            return True, f"Lấy Token thành công ({self.access_token[:15]}...)"

        except Exception as e:
            return False, f"Lỗi kết nối khi xử lý Cookie: {e}"

    # =========================================================================
    # 3. ĐĂNG NHẬP TỪ UID | PASS | 2FA
    # =========================================================================
    def login_with_account(self, uid: str, password: str, twofa_secret: str = None):
        url = "https://b-graph.facebook.com/auth/login"
        device_id = str(uuid.uuid4())
        family_device_id = str(uuid.uuid4())
        machine_id = "".join(uuid.uuid4().hex[:24])

        headers = {
            "User-Agent": self.user_agent,
            "Authorization": f"OAuth {self.fb4a_app_id}|{self.fb4a_client_token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-FB-HTTP-Engine": "Liger",
            "X-FB-Connection-Type": "MOBILE.LTE",
            "X-FB-Friendly-Name": "authenticate"
        }

        data = {
            "adid": str(uuid.uuid4()),
            "format": "json",
            "device_id": device_id,
            "family_device_id": family_device_id,
            "email": uid.strip(),
            "password": password.strip(),
            "cpl": "true",
            "try_num": "1",
            "credentials_type": "password",
            "generate_session_cookies": "1",
            "generate_machine_id": "1",
            "machine_id": machine_id,
            "meta_inf_fbmeta": "NO_FILE",
            "Currently_logged_in_userid": "0",
            "locale": "vi_VN",
            "client_country_code": "VN",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "com.facebook.account.login.protocol.Fb4aAuthHandler",
            "api_key": self.fb4a_app_id,
            "access_token": f"{self.fb4a_app_id}|{self.fb4a_client_token}"
        }

        try:
            res = self.session.post(url, headers=headers, data=data, timeout=25)
            res_json = res.json()

            if "access_token" in res_json:
                self.access_token = res_json["access_token"]
                self.cookie = self._parse_session_cookies(res_json.get("session_cookies", []))
                return True, "Đăng nhập thành công"

            error = res_json.get("error", {})
            error_data = error.get("error_data", {})
            if isinstance(error_data, str):
                error_data = json.loads(error_data)

            if error.get("code") == 406 or "login_first_factor" in error_data:
                if not twofa_secret:
                    return False, "Tài khoản yêu cầu 2FA nhưng chưa nhập mã 2FA"

                otp_code = self.get_totp_2fa(twofa_secret) if len(twofa_secret.strip()) > 6 else twofa_secret.strip()
                first_factor = error_data.get("login_first_factor")
                uid_2fa = str(error_data.get("uid", uid))

                data.update({
                    "credentials_type": "two_factor",
                    "email": uid_2fa,
                    "password": otp_code,
                    "twofactor_code": otp_code,
                    "first_factor": first_factor,
                    "userid": uid_2fa,
                    "machine_id": error_data.get("machine_id", machine_id)
                })

                res_2fa = self.session.post(url, headers=headers, data=data, timeout=25)
                res_2fa_json = res_2fa.json()

                if "access_token" in res_2fa_json:
                    self.access_token = res_2fa_json["access_token"]
                    self.cookie = self._parse_session_cookies(res_2fa_json.get("session_cookies", []))
                    return True, "Đăng nhập 2FA thành công"

                return False, res_2fa_json.get("error", {}).get("message", "Lỗi xác thực 2FA")

            return False, error.get("message", str(res_json))

        except Exception as e:
            return False, f"Lỗi kết nối Login: {e}"

    # =========================================================================
    # 4. API CHECK TOKEN, LẤY DANH SÁCH PAGE, REG PAGE & UP AVATAR
    # =========================================================================
    def check_token(self):
        url = "https://graph.facebook.com/me"
        params = {"fields": "id,name", "access_token": self.access_token}
        try:
            res = self.session.get(url, params=params, headers={"User-Agent": self.user_agent}, timeout=15)
            data = res.json()
            if "id" in data:
                self.uid = data["id"]
                return True, data.get("name", "")
            return False, data.get("error", {}).get("message", "Token Die")
        except Exception as e:
            return False, str(e)

    def get_my_pages(self):
        url = "https://graph.facebook.com/me/accounts"
        params = {
            "fields": "id,name,category,access_token",
            "limit": "100",
            "access_token": self.access_token
        }
        try:
            res = self.session.get(url, params=params, headers={"User-Agent": self.user_agent}, timeout=20)
            return res.json().get("data", [])
        except Exception:
            return []

    def reg_page(self, page_name: str = None, category_id: str = "180164648685982"):
        """Gọi API GraphQL Bloks tạo Page Profile Plus"""
        if not page_name:
            page_name = self.random_page_name()

        url = "https://graph.facebook.com/graphql"
        qpl_instance_id = float(f"5.50985{random.randint(10000000, 99999999)}E13")

        inner_params = {
            "client_input_params": {
                "page_id": "0",
                "profile_plus_id": "0",
                "cp_upsell_declined": 0,
                "off_platform_creator_reachout_id": "",
                "category_ids": [str(category_id)],
                "nav_chain": (
                    "ProfilePlusCreationNavigationReactNative,pages_tab_launch_point,,1678901234.567,101234567,,,;"
                    "ProfilePlusCreationActions,category,,1678901238.123,101234568,,,"
                )
            },
            "server_params": {
                "referrer": "pages_tab_launch_point",
                "INTERNAL__latency_qpl_marker_id": 36707139,
                "creation_source": "android",
                "name": page_name,
                "variant": 5,
                "screen": "category",
                "INTERNAL__latency_qpl_instance_id": qpl_instance_id
            }
        }

        outer_params = {
            "params": json.dumps(inner_params, ensure_ascii=False, separators=(',', ':'))
        }

        variables_dict = {
            "params": {
                "params": json.dumps(outer_params, ensure_ascii=False, separators=(',', ':')),
                "bloks_versioning_id": "338f8ead5977a2c41eba3e92584dcf1d132e8b7928f1f5796662ec064023047d",
                "app_id": "com.bloks.www.additional.profile.plus.creation.action.category.submit"
            },
            "scale": "2",
            "nt_context": {
                "using_white_navbar": True,
                "styles_id": "588d028b36bed0e1889e09b60e0f9aea",
                "pixel_ratio": 2,
                "is_push_on": True,
                "debug_tooling_metadata_token": None,
                "is_flipper_enabled": False,
                "theme_params": [{"value": [], "design_system_name": "FDS"}],
                "bloks_version": "338f8ead5977a2c41eba3e92584dcf1d132e8b7928f1f5796662ec064023047d"
            }
        }

        headers = {
            "User-Agent": self.user_agent,
            "Authorization": f"OAuth {self.access_token}",
            "X-FB-HTTP-Engine": "Liger",
            "X-FB-Connection-Type": "MOBILE.LTE",
            "X-FB-Connection-Quality": "EXCELLENT",
            "X-FB-Friendly-Name": "FBBloksActionRootQuery-com.bloks.www.additional.profile.plus.creation.action.category.submit",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        payload = {
            "method": "post",
            "pretty": "false",
            "format": "json",
            "server_timestamps": "true",
            "locale": "vi_VN",
            "purpose": "fetch",
            "fb_api_req_friendly_name": "FBBloksActionRootQuery-com.bloks.www.additional.profile.plus.creation.action.category.submit",
            "fb_api_caller_class": "graphservice",
            "client_doc_id": "119940804239956818821550724",
            "variables": json.dumps(variables_dict, ensure_ascii=False, separators=(',', ':')),
            "fb_api_analytics_tags": '["GraphServices"]',
            "client_trace_id": str(uuid.uuid4())
        }

        before_pages = {p["id"] for p in self.get_my_pages()}

        try:
            res = self.session.post(url, headers=headers, data=payload, timeout=30)
            res_text = res.text
            res_json = res.json()

            if "error" in res_json or "errors" in res_json:
                err_msg = res_json.get("error", {}).get("message") or str(res_json.get("errors"))
                return False, f"Lỗi GraphQL: {decode_unicode_text(err_msg)}"

            # Chờ 2.5s để đồng bộ danh sách Page mới
            time.sleep(2.5)
            after_pages = self.get_my_pages()

            for page in after_pages:
                if page["id"] not in before_pages:
                    return True, page

            # Bóc tách trực tiếp Page ID hoặc thông báo lỗi tiếng Việt trong gói Bloks
            if "bloks_bundle_action" in res_text:
                ids = re.findall(r'\b(615\d{11,13}|1000\d{10,12}|\d{14,16})\b', res_text)
                ignore_ids = {"180164648685982", "55098533200051", str(self.uid)}
                extracted = [i for i in ids if i not in ignore_ids]
                if extracted:
                    return True, {"id": extracted[0], "name": page_name, "access_token": ""}

                # Giải mã toàn bộ phản hồi Bloks sang tiếng Việt có dấu
                readable_text = decode_unicode_text(res_text)
                err_matches = re.findall(
                    r'"([^"]*?(?:Không thể|giới hạn|quá nhiều|thử lại|vi phạm|không hợp lệ)[^"]*?)"',
                    readable_text,
                    re.IGNORECASE
                )
                if err_matches:
                    return False, f"Facebook từ chối: {err_matches[0]}"

            return False, "Tài khoản đã chạm giới hạn tạo Page trong ngày hoặc IP mạng đang bị chặn tạm thời"

        except Exception as e:
            return False, f"Lỗi kết nối Reg Page: {e}"

    def upload_page_avatar(self, page_access_token: str, path_or_url: str) -> bool:
        """Hỗ trợ up Avatar từ: Thư mục ảnh trong máy, File ảnh lẻ trong máy, hoặc Link ảnh Online"""
        if not page_access_token or not path_or_url:
            return False

        clean_path = path_or_url.strip().strip('"').strip("'")
        if not clean_path:
            return False

        url = "https://graph.facebook.com/me/picture"

        try:
            # 1. Nếu là đường dẫn Thư mục (VD: D:\New folder\avatars) -> Chọn ngẫu nhiên 1 ảnh
            if os.path.isdir(clean_path):
                imgs = [
                    os.path.join(clean_path, f) for f in os.listdir(clean_path)
                    if f.lower().endswith((".jpg", ".jpeg", ".png", ".webp"))
                ]
                if not imgs:
                    safe_print(f"   [!] Không tìm thấy file ảnh (.jpg, .png) nào trong thư mục: {clean_path}")
                    return False
                clean_path = random.choice(imgs)

            # 2. Nếu là đường dẫn File ảnh trên máy tính -> Upload file trực tiếp
            if os.path.isfile(clean_path):
                with open(clean_path, "rb") as img_file:
                    res = self.session.post(
                        url,
                        data={"access_token": page_access_token},
                        files={"source": img_file},
                        headers={"User-Agent": self.user_agent},
                        timeout=30
                    )
                return res.status_code == 200 and "error" not in res.json()

            # 3. Nếu là Link ảnh trên mạng (http / https)
            if clean_path.startswith("http://") or clean_path.startswith("https://"):
                res = self.session.post(
                    url,
                    data={"url": clean_path, "access_token": page_access_token},
                    headers={"User-Agent": self.user_agent},
                    timeout=20
                )
                return res.status_code == 200 and "error" not in res.json()

            safe_print(f"   [!] Đường dẫn ảnh hoặc thư mục không tồn tại: {clean_path}")
            return False

        except Exception as e:
            safe_print(f"   [-] Lỗi khi up Avatar: {e}")
            return False


# =========================================================================
# HỖ TRỢ ĐỌC DÒNG TÀI KHOẢN & CHẠY ĐA LUỒNG
# =========================================================================
def parse_account_line(line: str) -> dict:
    parts = [p.strip() for p in line.strip().split("|") if p.strip()]
    result = {"type": None, "token": None, "cookie": None, "uid": None, "pass": None, "twofa": None, "proxy": None}
    if not parts:
        return result

    remaining = []
    for p in parts:
        if p.startswith("EAA"):
            result["token"] = p
        elif "c_user=" in p and "xs=" in p:
            result["cookie"] = p
        elif (":" in p and not p.startswith("http") and len(p.split(":")) in (2, 4)) or p.startswith("http://") or p.startswith("https://"):
            result["proxy"] = p
        else:
            remaining.append(p)

    if result["token"] or result["cookie"]:
        result["type"] = "TOKEN_OR_COOKIE"
    elif len(remaining) >= 2:
        result["type"] = "ACCOUNT"
        result["uid"] = remaining[0]
        result["pass"] = remaining[1]
        if len(remaining) >= 3:
            result["twofa"] = remaining[2]

    return result


def worker_task(index: int, line: str, config: dict):
    parsed = parse_account_line(line)
    if not parsed["type"]:
        safe_print(f"[Luồng {index}] Bỏ qua dòng sai định dạng: {line[:30]}...")
        return

    proxy = parsed["proxy"] or config.get("DEFAULT_PROXY")
    bot = FacebookAllInOne(proxy=proxy)
    is_live = False
    name_or_err = ""

    if parsed["type"] == "TOKEN_OR_COOKIE":
        if parsed["token"]:
            bot.access_token = bot.convert_token_to_eaaau(parsed["token"])
            is_live, name_or_err = bot.check_token()
        if not is_live and parsed["cookie"]:
            safe_print(f"[Luồng {index}] Đang lấy Token từ Cookie...")
            ok, msg = bot.login_with_cookie(parsed["cookie"])
            if ok:
                is_live, name_or_err = bot.check_token()
            else:
                name_or_err = msg
    elif parsed["type"] == "ACCOUNT":
        safe_print(f"[Luồng {index}] Đang đăng nhập UID: {parsed['uid']}...")
        ok, msg = bot.login_with_account(parsed["uid"], parsed["pass"], parsed["twofa"])
        if ok:
            is_live, name_or_err = bot.check_token()
        else:
            name_or_err = msg

    if not is_live:
        safe_print(f"[Luồng {index}] [-] Đăng nhập thất bại: {name_or_err}")
        save_line(FAILED_FILE, f"{line} | {name_or_err}")
        return

    safe_print(f"[Luồng {index}] [+] Via Live | UID: {bot.uid} ({name_or_err}) -> Bắt đầu tạo {config['PAGES_PER_ACC']} Page...")

    for i in range(config["PAGES_PER_ACC"]):
        p_name = bot.random_page_name()
        safe_print(f"[Luồng {index}] [*] ({bot.uid}) Đang tạo Page {i + 1}/{config['PAGES_PER_ACC']}: '{p_name}'...")
        ok, page_info = bot.reg_page(page_name=p_name)

        if ok and isinstance(page_info, dict):
            p_id = page_info.get("id", "")
            p_real_name = page_info.get("name", p_name)
            p_token = page_info.get("access_token", "")
            safe_print(f"[Luồng {index}] [SUCCESS] Tạo thành công: {p_real_name} | ID: {p_id}")

            if config.get("AVATAR_PATH") and p_token:
                if bot.upload_page_avatar(p_token, config["AVATAR_PATH"]):
                    safe_print(f"[Luồng {index}] [+] Đã cập nhật Avatar cho Page {p_id}")

            save_line(SUCCESS_FILE, f"{bot.uid}|{p_id}|{p_real_name}|{p_token}|{bot.access_token}")
        else:
            safe_print(f"[Luồng {index}] [-] ({bot.uid}) Tạo thất bại: {page_info}")
            break

        if i + 1 < config["PAGES_PER_ACC"]:
            time.sleep(config["DELAY_SEC"])


# =========================================================================
# GIAO DIỆN MENU CHÍNH TRÊN CMD
# =========================================================================
def run_interactive_mode():
    while True:
        print("\n" + "=" * 68)
        print("   CHẾ ĐỘ 1: NHẬP TRỰC TIẾP TOKEN / COOKIE / TÀI KHOẢN")
        print("=" * 68)
        raw_token = input("[1] Nhập Access Token (Nhấn Enter để bỏ qua nếu dùng Cookie)     : ").strip()
        raw_cookie = input("[2] Nhập Cookie (Nhấn Enter để bỏ qua nếu đã nhập Token)         : ").strip()

        raw_uid, raw_pass, raw_2fa = "", "", ""
        if not raw_token and not raw_cookie:
            print("[*] Bạn chưa nhập Token/Cookie -> Chuyển sang nhập UID | Pass | 2FA:")
            raw_uid = input("    -> Nhập UID      : ").strip()
            raw_pass = input("    -> Nhập Mật khẩu : ").strip()
            raw_2fa = input("    -> Nhập 2FA Key (Enter nếu không có): ").strip()
            if not raw_uid or not raw_pass:
                print("[-] Bạn phải nhập ít nhất Token, Cookie hoặc UID/Pass!")
                continue

        raw_proxy = input("[3] Nhập Proxy ip:port:user:pass (Nhấn Enter nếu không dùng)     : ").strip()
        so_luong_str = input("[4] Số lượng Page muốn tạo (Mặc định = 5)                        : ").strip()
        so_luong = int(so_luong_str) if so_luong_str.isdigit() else 5

        delay_str = input("[5] Thời gian nghỉ giữa mỗi lần tạo - giây (Mặc định = 10)       : ").strip()
        delay_sec = int(delay_str) if delay_str.isdigit() else 10

        custom_name = input("[6] Tên Page muốn đặt (Nhấn Enter để tự random tên Việt)         : ").strip()
        avatar_path = input("[7] Thư mục ảnh / File ảnh / Link ảnh Avatar (Enter để bỏ qua)   : ").strip()

        print("\n" + "-" * 68)
        bot = FacebookAllInOne(proxy=raw_proxy)
        is_live = False
        name_or_err = ""

        if raw_token:
            bot.access_token = bot.convert_token_to_eaaau(raw_token)
            is_live, name_or_err = bot.check_token()
            if not is_live:
                print(f"[!] Token nhập vào bị lỗi ({name_or_err}).")

        if not is_live and raw_cookie:
            print("[*] Đang lấy Token từ Cookie...")
            ok, msg = bot.login_with_cookie(raw_cookie)
            if ok:
                is_live, name_or_err = bot.check_token()
            else:
                name_or_err = msg

        if not is_live and raw_uid and raw_pass:
            print(f"[*] Đang đăng nhập UID {raw_uid}...")
            ok, msg = bot.login_with_account(raw_uid, raw_pass, raw_2fa)
            if ok:
                is_live, name_or_err = bot.check_token()
            else:
                name_or_err = msg

        if not is_live:
            print(f"[-] Đăng nhập thất bại: {name_or_err}")
        else:
            print(f"[+] Via Live! UID: {bot.uid} | Tên: {name_or_err}")
            print(f"[+] Token đang dùng: {bot.access_token[:35]}...")

            for i in range(so_luong):
                p_name = f"{custom_name} {i + 1}" if (custom_name and so_luong > 1) else (custom_name or bot.random_page_name())
                print(f"\n[*] [{i + 1}/{so_luong}] Đang tạo Page: '{p_name}'...")

                ok, page_info = bot.reg_page(page_name=p_name)
                if ok and isinstance(page_info, dict):
                    p_id = page_info.get("id", "")
                    p_real_name = page_info.get("name", p_name)
                    p_token = page_info.get("access_token", "")

                    print(f"[SUCCESS] TẠO PAGE THÀNH CÔNG!")
                    print(f"   -> Tên Page  : {p_real_name}")
                    print(f"   -> Page ID   : {p_id}")
                    if p_token:
                        print(f"   -> Token Page: {p_token[:40]}...")

                    if avatar_path and p_token:
                        print("   [*] Đang tải ảnh Avatar lên Page...")
                        if bot.upload_page_avatar(p_token, avatar_path):
                            print("   -> Đã cập nhật Avatar thành công!")

                    save_line(SUCCESS_FILE, f"{bot.uid}|{p_id}|{p_real_name}|{p_token}|{bot.access_token}")
                    print(f"   -> Đã lưu vào : {SUCCESS_FILE}")
                else:
                    print(f"[-] Tạo thất bại: {page_info}")
                    break

                if i + 1 < so_luong:
                    print(f"[*] Nghỉ {delay_sec} giây trước khi tạo tiếp...")
                    time.sleep(delay_sec)

        tiep = input("\n[?] Bạn có muốn chạy tiếp tài khoản khác không? (y/n): ").strip().lower()
        if tiep != "y":
            break


def run_batch_file_mode():
    print("\n" + "=" * 68)
    print("   CHẾ ĐỘ 2: CHẠY ĐA LUỒNG TỪ FILE ACCOUNTS.TXT")
    print("=" * 68)

    if not os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
            f.write("# Dán mỗi dòng 1 tài khoản (Token, Cookie, Cookie|Token, hoặc UID|Pass|2FA)\n")
        print(f"[!] Đã tạo file mẫu tại: {ACCOUNTS_FILE}")
        print("[!] Hãy mở file đó, dán danh sách Token/Cookie vào rồi chạy lại!")
        return

    with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not lines:
        print(f"[-] File {ACCOUNTS_FILE} đang trống! Hãy dán tài khoản vào trước.")
        return

    print(f"[+] Đã tìm thấy {len(lines)} tài khoản trong file accounts.txt.")
    threads_str = input("[1] Nhập số luồng chạy cùng lúc (Mặc định = 3)                   : ").strip()
    pages_str = input("[2] Số lượng Page muốn tạo mỗi acc (Mặc định = 4)                : ").strip()
    delay_str = input("[3] Thời gian nghỉ giữa mỗi lần tạo - giây (Mặc định = 10)       : ").strip()
    avatar_path = input("[4] Thư mục ảnh / File ảnh / Link ảnh Avatar (Enter để bỏ qua)   : ").strip()
    default_proxy = input("[5] Proxy dùng chung ip:port:user:pass (Enter nếu không dùng)    : ").strip()

    config = {
        "MAX_THREADS": int(threads_str) if threads_str.isdigit() else 3,
        "PAGES_PER_ACC": int(pages_str) if pages_str.isdigit() else 4,
        "DELAY_SEC": int(delay_str) if delay_str.isdigit() else 10,
        "AVATAR_PATH": avatar_path if avatar_path else None,
        "DEFAULT_PROXY": default_proxy if default_proxy else None
    }

    print(f"\n[*] Đang khởi chạy {config['MAX_THREADS']} luồng...\n")
    with ThreadPoolExecutor(max_workers=config["MAX_THREADS"]) as executor:
        futures = [executor.submit(worker_task, idx + 1, line, config) for idx, line in enumerate(lines)]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"[-] Lỗi luồng: {e}")

    print("\n[=== ĐÃ CHẠY XONG TOÀN BỘ DANH SÁCH ===]")
    print(f"-> Kết quả lưu tại: {SUCCESS_FILE}")


def main():
    os.system("cls" if os.name == "nt" else "clear")
    print("=" * 68)
    print("      TOOL REG PAGE PROFILE PLUS FULL API (TOKEN / COOKIE)")
    print("=" * 68)
    print("  [1] Nhập trực tiếp Token / Cookie trên màn hình CMD (Chạy lẻ)")
    print("  [2] Chạy hàng loạt đa luồng từ file accounts.txt")
    print("=" * 68)

    choice = input("-> Chọn chế độ chạy (1 hoặc 2, mặc định là 1): ").strip()
    if choice == "2":
        run_batch_file_mode()
    else:
        run_interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Đã dừng chương trình.")
    input("\nNhấn phím Enter để thoát...")
