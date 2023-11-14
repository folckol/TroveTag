import json
import random
import re
import ssl
import imaplib
import email
import time
import traceback

from web3 import Web3

import capmonster_python
import requests
import cloudscraper
from eth_account.messages import encode_defunct
from web3.auto import w3

def random_user_agent():
    browser_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_{2}_{3}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{1}.{2}) Gecko/20100101 Firefox/{1}.{2}',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{0}.{1}.{2} Edge/{3}.{4}.{5}'
    ]

    chrome_version = random.randint(70, 108)
    firefox_version = random.randint(70, 108)
    safari_version = random.randint(605, 610)
    edge_version = random.randint(15, 99)

    chrome_build = random.randint(1000, 9999)
    firefox_build = random.randint(1, 100)
    safari_build = random.randint(1, 50)
    edge_build = random.randint(1000, 9999)

    browser_choice = random.choice(browser_list)
    user_agent = browser_choice.format(chrome_version, firefox_version, safari_version, edge_version, chrome_build, firefox_build, safari_build, edge_build)

    return user_agent

def get_last_mail(login, password):
    count = 0
    while count < 5:

        # Введите свои данные учетной записи
        email_user = login
        email_pass = password

        if '@rambler' in login or '@lenta' in login or '@autorambler' in login or '@ro' in login:
            # Подключение к серверу IMAP
            mail = imaplib.IMAP4_SSL("imap.rambler.ru")

        else:
            mail = imaplib.IMAP4_SSL("imap.mail.ru")

        mail.login(email_user, email_pass)

        # Выбор почтового ящика
        mail.select("inbox")

        # Поиск писем с определенной темой
        typ, msgnums = mail.search(None, 'SUBJECT "Trove Email Verification"')
        msgnums = msgnums[0].split()

        # Обработка писем
        link = ''

        for num in msgnums:
            typ, data = mail.fetch(num, "(BODY[TEXT])")
            msg = email.message_from_bytes(data[0][1])
            text = msg.get_payload(decode=True).decode()

            # print(text.replace('=\r\n', '').split('<a href=3D"')[1].split('" target=3D"')[0])

            # Поиск ссылки в тексте письма
            link_pattern = r'https://trove-api.treasure.lol/account/verify-email\S*'
            match = re.search(link_pattern, text.replace('=\r\n', '').replace('"', ' '))

            # ('\n\printn')
            if match:
                link = match.group().replace("verify-email?token=3D", "verify-email?token=").replace("&email=3D", "&email=").replace("&redirectUrl=3D", "&redirectUrl=")
                # print(f"Найдена ссылка: \n\n{link}")
            else:
                # print("Ссылка не найдена")
                count += 1
                time.sleep(2)

        # Завершение сессии и выход
        mail.close()
        mail.logout()

        if link != '':
            return link

    return None



def register_f(web3, address, private_key, params, authority_signature, id):
    my_address = address
    nonce = web3.eth.get_transaction_count(w3.to_checksum_address(my_address))
    who_swap = w3.to_checksum_address(my_address)

    with open('abi.json') as f:
        abi = json.load(f)

    contract = web3.eth.contract(w3.to_checksum_address('0x072b65f891b1a389539e921bdb9427af41a7b1f7'), abi=abi)

    register = contract.get_function_by_selector("0x95f38e77")
    # print(params)
    params = {
        'name': params[0],
        'discriminant': params[1],
        'owner': who_swap,
        'resolver': w3.to_checksum_address(params[2]),
        'nonce': int(params[3], 16),
    }


    transaction = register(params, authority_signature).build_transaction(
        {
            "chainId": web3.eth.chain_id,
            "gasPrice": web3.eth.gas_price,
            "from": who_swap,
            "value": 0,
            "nonce": nonce,
        }
    )

    signed_txn = web3.eth.account.sign_transaction(
        transaction, private_key=private_key
    )

    raw_tx_hash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    # print(f'{id} - Transaction signed')
    return web3.to_hex(raw_tx_hash)


class Trove:

    def __init__(self, accs_data, cap_key, id):

        self.id = id
        self.cap_key = cap_key
        self.address = accs_data['address']
        self.private_key = accs_data['private_key']
        self.tw_auth_token = accs_data['tw_auth_token']
        self.tw_csrf = accs_data['tw_csrf']
        self.discord_token = accs_data['discord_token']
        # self.mail = accs_data['mail']
        # self.mail_pass = accs_data['mail_pass']


        self.proxy = {'http': accs_data['proxy'], 'https': accs_data['proxy']}
        self.static_sitekey = '6LeVGhkkAAAAAIHfvKTSepWAwYiccTiLvGuDXG_V'

        self.session = self._make_scraper()
        adapter = requests.adapters.HTTPAdapter(max_retries=10)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.session.proxies = self.proxy
        self.session.user_agent = random_user_agent()

    def execute_task(self):
        # try:

        self.status_event = 'Ready'

        # self.token = self.Authorize()

        try:
            self.session.headers.update({'authorization': self.Authorize()})

            with self.session.get('https://trove-api.treasure.lol/account/settings', timeout=15) as response:
                pass
        except:
            self.status_event = 'Authorize Error'
            return self.status_event


        try:
            link = ''
            while link == '' or link == None:
                try:
                    with open('account_files/mails.txt', 'r') as file:
                        lines = file.readlines()
                    mail_data = lines[0].split(':')
                    self.mail = mail_data[0]
                    self.mail_pass = mail_data[1]
                    with open('account_files/mails.txt', 'w') as file:
                        file.writelines(lines[1:])

                    self.Add_Mail()
                    time.sleep(5)
                    link = get_last_mail(self.mail, self.mail_pass)
                except IndexError:
                    self.status_event = 'Emails Over '
                    return self.status_event
                except:
                    pass

            self.session.get(link, timeout=15)
        except:
            self.status_event = 'Email Approve Error'
            return self.status_event


        try:
            self.Connect_Twitter()
            self.session.headers.update({'authorization': self.Authorize()})
        except:
            self.status_event = 'Twitter Error'
            return self.status_event

        try:
            self.Connect_Discord()
            self.session.headers.update({'authorization': self.Authorize()})
        except:
            self.status_event = 'Discord Error'
            return self.status_event


        status = False
        while status == False:

            self.tag = ''
            with open('account_files/tags.txt', 'r') as file:
                lines = file.readlines()
            self.tag = lines[0].strip('\n')
            with open('account_files/tags.txt', 'w') as file:
                file.writelines(lines[1:])

            status = self.Tag_status(self.tag.split('#')[0], self.tag.split('#')[1])

        if status == True:

            captcha = self.Captcha_Solver()
            # print(self.tag)

            payload = {"treasuretag": self.tag,
                       "recaptchaResponse": captcha}
            # print(payload)

            self.session.headers.update({'dnt':'1',
                                         'accept': '*/*',
                                         'content-type': 'application/json'})

            try:
                with self.session.post('https://trove-api.treasure.lol/account/reserve-treasuretag', json=payload, timeout=15) as response:
                    web3 = Web3(Web3.HTTPProvider('https://arb1.arbitrum.io/rpc'))
                    # print(response.text)
                    name = response.json()['claim']['registerArgs']['name']
                    discriminant = response.json()['claim']['registerArgs']['discriminant']
                    resolver = response.json()['claim']['registerArgs']['resolver']
                    nonce = response.json()['claim']['registerArgs']['nonce']
                    authority_signature = response.json()['claim']['authoritySignature']
                    # print(response.json()['claim']['registerArgs'])
                    params = [name, discriminant, resolver, nonce]
                    a = register_f(web3, self.address, self.private_key, params, authority_signature, self.id)

                    with open('results.txt', 'a+') as file:
                        file.write(f'{self.address} - {self.tag}\n')

                    return self.status_event
            except:

                traceback.print_exc()

                self.status_event = 'Transaction Error'
                return self.status_event



        # except:
        #     print(f'{self.id} - Error')

    def Captcha_Solver(self):
        cap = capmonster_python.RecaptchaV2Task(self.cap_key)
        tt = cap.create_task("https://trove.treasure.lol/", self.static_sitekey)
        captcha = cap.join_task_result(tt)
        captcha = captcha["gRecaptchaResponse"]
        return captcha

    def Tag_status(self, name, tag):
        with self.session.get(f'https://trove-api.treasure.lol/account/treasuretag-availability?treasureTag={name}%23{tag}', timeout=15) as response:
            # print(response.json())
            status = response.json()['isAvailable']
            return status


    def Connect_Discord(self):

        payload = {"redirectUrl":"https://trove.treasure.lol/treasuretag?edit=true"}
        with self.session.post('https://trove-api.treasure.lol/account/discord/login', json=payload, timeout=15) as response:
            url = response.json()['loginUrl']

            state = url.split('state=')[-1].split('&')[0]
            client_id = url.split('client_id=')[-1].split('&')[0]

            discord_headers = {
                'authority': 'discord.com',
                'authorization': self.discord_token,
                'content-type': 'application/json',
                'referer': f'https://discord.com/oauth2/authorize?client_id={client_id}&redirect_uri=https%3A%2F%2Ftrove-api.treasure.lol%2Fdiscord%2Fcallback&response_type=code&scope=identify%20guilds%20guilds.members.read&state={state}',
                'x-super-properties': 'eyJvcyI6Ik1hYyBPUyBYIiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJydS1SVSIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMDkuMC4wLjAgU2FmYXJpLzUzNy4zNiIsImJyb3dzZXJfdmVyc2lvbiI6IjEwOS4wLjAuMCIsIm9zX3ZlcnNpb24iOiIxMC4xNS43IiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjE3NDA1MSwiY2xpZW50X2V2ZW50X3NvdXJjZSI6bnVsbCwiZGVzaWduX2lkIjowfQ==',
            }

            payload = {"permissions":"0","authorize":True}

            with self.session.post(f'https://discord.com/api/v9/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri=https%3A%2F%2Ftrove-api.treasure.lol%2Fdiscord%2Fcallback&scope=identify%20guilds%20guilds.members.read&state={state}', json=payload, timeout=15, headers=discord_headers) as response:
                url = response.json()['location']

                with self.session.get(url, timeout=15) as response:
                    # print(f'{self.id} - Discord connected')
                    pass

    def Connect_Twitter(self):

        payload = {"redirectUrl":"https://trove.treasure.lol/treasuretag?edit=true"}
        with self.session.post('https://trove-api.treasure.lol/account/twitter/login', json=payload, timeout=15, allow_redirects=False) as response:

            url = response.json()['loginUrl']

            state = url.split('state=')[-1].split('&')[0]
            code_challenge = url.split('code_challenge=')[-1].split('&')[0]
            client_id = url.split('client_id=')[-1].split('&')[0]

            self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})

            # print(self.tw_auth_token, self.tw_csrf)

            with self.session.get(url, timeout=10, allow_redirects=False) as response:

                # with self.session.get('https://api.twitter.com/graphql/lFi3xnx0auUUnyG4YwpCNw/GetUserClaims?variables=%7B%7D', timeout=15) as response:
                #     pass

                self.session.headers.update({'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
                                             'x-twitter-auth-type': 'OAuth2Session',
                                             'x-csrf-token': self.tw_csrf})
                self.session.cookies.update({'auth_token': self.tw_auth_token, 'ct0': self.tw_csrf})
                time.sleep(1)

                with self.session.get(f'https://api.twitter.com/2/oauth2/authorize?code_challenge={code_challenge}&code_challenge_method=plain&client_id={client_id}&redirect_uri=https%3A%2F%2Ftrove-api.treasure.lol%2Ftwitter%2Fcallback&response_type=code&scope=tweet.read%20users.read%20follows.read%20space.read%20like.read%20list.read%20offline.access&state={state}', timeout=15, allow_redirects=True) as response:
                    code = response.json()['auth_code']

                    payload = {'approval':'true',
                               'code': code}

                    self.session.headers.update({'content-type':'application/x-www-form-urlencoded'})
                    time.sleep(1)
                    with self.session.post('https://api.twitter.com/2/oauth2/authorize', data=payload, timeout=15) as response:
                        time.sleep(1)
                        # print(response.text)
                        url = response.json()['redirect_uri']
                        with self.session.get(url, timeout=15) as response:
                            # print(f'{self.id} - Twitter connected')
                            pass

    def Add_Mail(self):
        payload = {'email': self.mail}
        with self.session.post('https://trove-api.treasure.lol/account/register', json=payload, timeout=15) as response:
            payload = {"redirectUrl":"https://trove.treasure.lol/treasuretag?edit=true"}
            with self.session.post('https://trove-api.treasure.lol/account/send-email-verification', json=payload, timeout=15) as response:
                # print(response.text)
                # print(f'{self.id} - Email sent')
                pass

    def Authorize(self):

        self.nonce = self._get_nonce()[1:-1]
        message = encode_defunct(text=self._get_message_to_sign(self.nonce))
        signed_message = w3.eth.account.sign_message(message, private_key=self.private_key)
        self.signature = signed_message["signature"].hex()

        payload = {"account":self.address,
                   "message":f"\n      Welcome to Trove! Please sign this message to verify account ownership.\n      \n      One time use code:\n      {self.nonce}",
                   "signature":self.signature,
                   "code":self.nonce}
        with self.session.post('https://trove-api.treasure.lol/session', json=payload, timeout=10) as response:
            return response.json()['sessionToken']

    def _get_message_to_sign(self, nonce) -> str:
        return f"\n      Welcome to Trove! Please sign this message to verify account ownership.\n      \n      One time use code:\n      {nonce}"

    def _get_nonce(self):
        try:
            self.session.headers.update({'content-type': 'application/json'})
            payload = {'account': self.address}
            with self.session.post("https://trove-api.treasure.lol/auth",json=payload, timeout=15) as response:
                if response.ok:
                    nonce = response.text
                    return nonce
                else:
                    # print(f"Unknown status code while getting nonce [{response.status_code}]")
                    # print(response.text)
                    print('error')
        except Exception as err:
            print('error')

    def _make_scraper(self):
        ssl_context = ssl.create_default_context()
        ssl_context.set_ciphers(
            "ECDH-RSA-NULL-SHA:ECDH-RSA-RC4-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-RSA-AES128-SHA:ECDH-RSA-AES256-SHA:"
            "ECDH-ECDSA-NULL-SHA:ECDH-ECDSA-RC4-SHA:ECDH-ECDSA-DES-CBC3-SHA:ECDH-ECDSA-AES128-SHA:"
            "ECDH-ECDSA-AES256-SHA:ECDHE-RSA-NULL-SHA:ECDHE-RSA-RC4-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-SHA:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-NULL-SHA:ECDHE-ECDSA-RC4-SHA:ECDHE-ECDSA-DES-CBC3-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:AECDH-NULL-SHA:AECDH-RC4-SHA:AECDH-DES-CBC3-SHA:"
            "AECDH-AES128-SHA:AECDH-AES256-SHA"
        )
        ssl_context.set_ecdh_curve("prime256v1")
        ssl_context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1)
        ssl_context.check_hostname = False

        return cloudscraper.create_scraper(
            debug=False,
            ssl_context=ssl_context
        )



