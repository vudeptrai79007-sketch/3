import os
import re
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

# Khóa đồng bộ khi in log và ghi file đa luồng
print_lock = threading.Lock()
file_lock = threading.Lock()


def safe_print(msg: str):
    with print_lock:
        print(msg)


def save_line(filename: str, content: str):
    with file_lock:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(content.strip() + "\n")


class FacebookAllInOne:
    def __init__(self, proxy: str = None):
        self.session = requests.Session()
        if proxy:
            proxy = proxy.strip()
            if not proxy.startswith("http"):
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
        suffix = ["Official", "Vlog", "Blog", "Store", "Shop", "Media", "Daily", "News", "24h", "TV"]

        if random.choice([True, False]):
            return f"{random.choice(ho)} {random.choice(dem)} {random.choice(ten)}"
        return f"{random.choice(ho)} {random.choice(ten)} {random.choice(suffix)}"

    @staticmethod
    def get_totp_2fa(secret_key: str) -> str:
        """Tự giải mã 6 số 2FA từ chuỗi Secret Key"""
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
    # 1. LẤY TOKEN EAAAAU TỪ UID | PASS | 2FA
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
                return True, "Login thành công"

            error = res_json.get("error", {})
            error_data = error.get("error_data", {})
            if isinstance(error_data, str):
                error_data = json.loads(error_data)

            # Xử lý xác thực 2 yếu tố (2FA)
            if error.get("code") == 406 or "login_first_factor" in error_data:
                if not twofa_secret:
                    return False, "Tài khoản có 2FA nhưng thiếu mã 2FA Secret"

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
                    return True, "Login 2FA thành công"

                return False, res_2fa_json.get("error", {}).get("message", "Lỗi xác thực 2FA")

            return False, error.get("message", str(res_json))

        except Exception as e:
            return False, f"Lỗi kết nối khi Login: {e}"

    # =========================================================================
    # 2. LẤY TOKEN EAAAAU TỪ COOKIE
    # =========================================================================
    def login_with_cookie(self, cookie: str):
        self.cookie = cookie.strip()
        web_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Cookie": self.cookie,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate"
        }

        try:
            base_token = None
            res = self.session.get("https://business.facebook.com/business_locations", headers=web_headers, timeout=20)
            match_eaag = re.search(r'(EAAG\w+)', res.text)
            if match_eaag:
                base_token = match_eaag.group(1)

            if not base_token:
                res_ads = self.session.get("https://adsmanager.facebook.com/adsmanager/manage/campaigns", headers=web_headers, timeout=20)
                act_match = re.search(r'act=(\d+)', res_ads.text) or re.search(r'act=(\d+)', res_ads.url)
                if act_match:
                    url_act = f"https://adsmanager.facebook.com/adsmanager/manage/campaigns?act={act_match.group(1)}"
                    res_act = self.session.get(url_act, headers=web_headers, timeout=20)
                    match_eaa = re.search(r'(EAA[a-zA-Z0-9]+)', res_act.text)
                    if match_eaa:
                        base_token = match_eaa.group(1)

            if not base_token:
                return False, "Cookie Die hoặc không lấy được Token trung gian"

            # Đổi sang Token EAAAAU của App Android
            convert_url = "https://api.facebook.com/method/auth.getSessionforApp"
            params = {
                "access_token": base_token,
                "format": "json",
                "new_app_id": self.fb4a_app_id,
                "generate_session_cookies": "1"
            }
            res_conv = self.session.get(convert_url, params=params, headers={"User-Agent": self.user_agent}, timeout=20)
            conv_json = res_conv.json()

            if "access_token" in conv_json:
                self.access_token = conv_json["access_token"]
                return True, "Đổi Cookie sang EAAAAU thành công"

            self.access_token = base_token
            return True, "Dùng Token gốc từ Cookie (không đổi được sang EAAAAU)"

        except Exception as e:
            return False, f"Lỗi xử lý Cookie: {e}"

    # =========================================================================
    # 3. CÁC API FACEBOOK (CHECK TOKEN, GET PAGES, REG PAGE, UP AVATAR)
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
                return False, f"Lỗi GraphQL: {err_msg}"

            time.sleep(2.5)
            after_pages = self.get_my_pages()

            for page in after_pages:
                if page["id"] not in before_pages:
                    return True, page

            # Dự phòng bóc ID trực tiếp từ Bloks bundle nếu API /me/accounts cập nhật chậm
            if "bloks_bundle_action" in res_text:
                ids = re.findall(r'\b(615\d{11,13}|1000\d{10,12}|\d{14,16})\b', res_text)
                ignore_ids = {"180164648685982", "55098533200051", str(self.uid)}
                extracted = [i for i in ids if i not in ignore_ids]
                if extracted:
                    return True, {"id": extracted[0], "name": page_name, "access_token": ""}

            return False, "Không thấy Page mới (Tài khoản bị giới hạn tạo Page hoặc tên bị từ chối)"

        except Exception as e:
            return False, f"Lỗi kết nối Reg Page: {e}"

    def upload_page_avatar(self, page_access_token: str, image_url: str) -> bool:
        if not page_access_token or not image_url:
            return False
        url = "https://graph.facebook.com/me/picture"
        data = {"url": image_url, "access_token": page_access_token}
        try:
            res = self.session.post(url, data=data, headers={"User-Agent": self.user_agent}, timeout=20)
            return res.status_code == 200 and "error" not in res.json()
        except Exception:
            return False


# =========================================================================
# HÀM PHÂN TÍCH DÒNG TÀI KHOẢN & LUỒNG WORKER
# =========================================================================
def parse_account_line(line: str) -> dict:
    """
    Tự động nhận diện các định dạng:
    1. EAAAAU... (hoặc EAAAAU...|proxy)
    2. c_user=...; xs=... (hoặc cookie|proxy)
    3. UID|PASS|2FA (hoặc UID|PASS|2FA|COOKIE|PROXY)
    """
    parts = [p.strip() for p in line.strip().split("|") if p.strip()]
    result = {"type": None, "token": None, "cookie": None, "uid": None, "pass": None, "twofa": None, "proxy": None}

    if not parts:
        return result

    # Kiểm tra nếu cột cuối cùng là Proxy (chứa dấu : và không phải cookie)
    if len(parts) > 1 and ":" in parts[-1] and "c_user=" not in parts[-1] and not parts[-1].startswith("EAA"):
        result["proxy"] = parts.pop(-1)

    first = parts[0]
    if first.startswith("EAA"):
        result["type"] = "TOKEN"
        result["token"] = first
    elif "c_user=" in first and "xs=" in first:
        result["type"] = "COOKIE"
        result["cookie"] = first
    elif len(parts) >= 2:
        result["type"] = "ACCOUNT"
        result["uid"] = parts[0]
        result["pass"] = parts[1]
        for item in parts[2:]:
            if "c_user=" in item:
                result["cookie"] = item
            else:
                result["twofa"] = item
    return result


def worker_task(index: int, line: str, config: dict):
    parsed = parse_account_line(line)
    if not parsed["type"]:
        safe_print(f"[Luồng {index}] Bỏ qua dòng sai định dạng: {line[:30]}...")
        return

    proxy = parsed["proxy"] or config.get("DEFAULT_PROXY")
    bot = FacebookAllInOne(proxy=proxy)

    # Bước 1: Lấy Access Token theo định dạng đầu vào
    if parsed["type"] == "TOKEN":
        bot.access_token = parsed["token"]
    elif parsed["type"] == "COOKIE":
        safe_print(f"[Luồng {index}] Đang lấy Token EAAAAU từ Cookie...")
        ok, msg = bot.login_with_cookie(parsed["cookie"])
        if not ok:
            safe_print(f"[Luồng {index}] [-] Thất bại: {msg}")
            save_line("failed_accounts.txt", f"{line} | {msg}")
            return
    elif parsed["type"] == "ACCOUNT":
        safe_print(f"[Luồng {index}] Đang đăng nhập UID: {parsed['uid']}...")
        ok, msg = bot.login_with_account(parsed["uid"], parsed["pass"], parsed["twofa"])
        if not ok and parsed["cookie"]:
            safe_print(f"[Luồng {index}] Login Pass lỗi ({msg}), chuyển sang thử bằng Cookie...")
            ok, msg = bot.login_with_cookie(parsed["cookie"])
        if not ok:
            safe_print(f"[Luồng {index}] [-] Đăng nhập thất bại ({parsed['uid']}): {msg}")
            save_line("failed_accounts.txt", f"{line} | {msg}")
            return

    # Bước 2: Kiểm tra Token Live
    is_live, name_or_err = bot.check_token()
    if not is_live:
        safe_print(f"[Luồng {index}] [-] Token Die: {name_or_err}")
        save_line("failed_accounts.txt", f"{line} | Token Die: {name_or_err}")
        return

    safe_print(f"[Luồng {index}] [+] Via Live | UID: {bot.uid} ({name_or_err}) -> Bắt đầu Reg {config['PAGES_PER_ACC']} Page...")

    # Bước 3: Tiến hành Reg Page theo số lượng cấu hình
    for i in range(config["PAGES_PER_ACC"]):
        page_name = bot.random_page_name()
        safe_print(f"[Luồng {index}] [*] ({bot.uid}) Đang tạo Page {i + 1}/{config['PAGES_PER_ACC']}: '{page_name}'...")

        ok, page_info = bot.reg_page(page_name=page_name, category_id=config["CATEGORY_ID"])
        if ok and isinstance(page_info, dict):
            p_id = page_info.get("id", "")
            p_name = page_info.get("name", page_name)
            p_token = page_info.get("access_token", "")

            safe_print(f"[Luồng {index}] [SUCCESS] Tạo thành công Page: {p_name} | ID: {p_id}")

            # Tự động up Avatar nếu có cấu hình link ảnh và lấy được Token Page
            if config.get("AVATAR_URL") and p_token:
                if bot.upload_page_avatar(p_token, config["AVATAR_URL"]):
                    safe_print(f"[Luồng {index}] [+] Đã cập nhật Avatar cho Page {p_id}")

            # Lưu kết quả: UID_VIA | PAGE_ID | PAGE_NAME | PAGE_TOKEN | TOKEN_VIA
            save_line("success_pages.txt", f"{bot.uid}|{p_id}|{p_name}|{p_token}|{bot.access_token}")
        else:
            safe_print(f"[Luồng {index}] [-] ({bot.uid}) Tạo thất bại: {page_info}")
            # Nếu tài khoản bị chặn/giới hạn tạo Page thì dừng luôn tài khoản đó
            break

        if i + 1 < config["PAGES_PER_ACC"]:
            time.sleep(config["DELAY_BETWEEN_PAGES"])


if __name__ == "__main__":
    # ==================== CẤU HÌNH HỆ THỐNG ====================
    CONFIG = {
        "INPUT_FILE": "accounts.txt",
        "MAX_THREADS": 3,                        # Số luồng chạy song song
        "PAGES_PER_ACC": 4,                      # Số lượng Page muốn tạo trên mỗi Via
        "DELAY_BETWEEN_PAGES": 10,               # Nghỉ giữa mỗi lần tạo Page (giây)
        "CATEGORY_ID": "180164648685982",        # ID Danh mục (180164648685982 = Người sáng tạo nội dung số)
        "AVATAR_URL": None,                      # Điền link ảnh (VD: "https://i.imgur.com/abc.jpg") hoặc để None
        "DEFAULT_PROXY": None                    # Proxy mặc định nếu trong file không gắn kèm (VD: "user:pass@ip:port")
    }
    # ===========================================================

    # Tạo file mẫu nếu chưa tồn tại
    if not os.path.exists(CONFIG["INPUT_FILE"]):
        with open(CONFIG["INPUT_FILE"], "w", encoding="utf-8") as f:
            f.write("# Hỗ trợ 3 định dạng (mỗi tài khoản 1 dòng, có thể thêm |proxy ở cuối dòng):\n")
            f.write("# 1. EAAAAU...\n")
            f.write("# 2. c_user=1000xxx; xs=xxx;\n")
            f.write("# 3. 1000xxx|MatKhau|MA_2FA_SECRET\n")
        print(f"[!] Đã tạo file '{CONFIG['INPUT_FILE']}'. Hãy dán danh sách Via/Token/Cookie vào file rồi chạy lại!")
        exit(0)

    with open(CONFIG["INPUT_FILE"], "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not lines:
        print(f"[!] File '{CONFIG['INPUT_FILE']}' đang trống. Hãy thêm tài khoản vào trước khi chạy!")
        exit(0)

    print(f"[*] Đã tải {len(lines)} tài khoản. Khởi chạy {CONFIG['MAX_THREADS']} luồng...")

    with ThreadPoolExecutor(max_workers=CONFIG["MAX_THREADS"]) as executor:
        futures = [
            executor.submit(worker_task, idx + 1, line, CONFIG)
            for idx, line in enumerate(lines)
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:
                safe_print(f"[-] Lỗi ngoại lệ trong luồng: {exc}")

    print("\n[=== HOÀN TẤT TOÀN BỘ QUÁ TRÌNH ===]")
    print("-> Danh sách Page tạo thành công được lưu tại: success_pages.txt")
    print("-> Danh sách Via lỗi được lưu tại            : failed_accounts.txt")
