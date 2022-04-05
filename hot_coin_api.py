# -*- coding:UTF-8 -*-
# !/usr/bin/env python
import hmac
import hashlib
import requests
import base64

import urllib
from datetime import datetime


def get_utc_str():
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def http_post_request(url, params, timeout=10):
    # lang valueRange ： en_US,ko_KR,zh_CN
    header = {'lang': 'en_US'}
    response = requests.post(url, params, timeout=timeout, headers=header)
    if response.status_code == 200:
        return response.json()
    else:
        return


def http_get_request(url, params, timeout=10):
    # lang valueRange ： en_US,ko_KR,zh_CN
    header = {'lang': 'zh_CN'}
    response = requests.get(url, params, timeout=timeout, headers=header)
    if response.status_code == 200:
        return response.json()
    else:
        return


class HotCoin:
    def __init__(self, API_HOST='api.hotcoinfin.com', symbol=""):
        self.secret = None
        self.key = None
        self.API_HOST = 'api.hotcoinfin.com'
        self.API_RUL = 'https://' + self.API_HOST + '/v1/'
        self.symbol = symbol
        if not self.symbol:
            print("Init error, please add symbol")
        requests.packages.urllib3.disable_warnings()

    def auth(self, key, secret):
        self.key = bytes(key, 'utf-8')
        self.secret = bytes(secret, 'utf-8')

    def public_request(self, method, api_url, **payload):
        """request public url"""
        r_url = self.API_RUL + api_url
        # print(r_url)
        try:
            r = requests.request(method, r_url, params=payload)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            print(err)
        if r.status_code == 200:
            return r.json()

    def paramsSign(self, params, paramsPrefix, accessSecret):
        host = self.API_HOST
        method = paramsPrefix['method'].upper()
        uri = paramsPrefix['uri']
        tempParams = urllib.parse.urlencode(sorted(params.items(), key=lambda d: d[0], reverse=False))
        payload = '\n'.join([method, host, uri, tempParams]).encode(encoding='UTF-8')
        # accessSecret = accessSecret.encode(encoding='UTF-8')
        return base64.b64encode(hmac.new(accessSecret, payload, digestmod=hashlib.sha256).digest())

    def api_key_request(self, method, API_URI, **params):
        """request a signed url"""
        if not self.key or not self.secret:
            print("Please config api key and secret")
            exit(-1)
        params_to_sign = {'AccessKeyId': self.key,
                          'SignatureMethod': 'HmacSHA256',
                          'SignatureVersion': '2',
                          'Timestamp': get_utc_str()}
        host_name = urllib.parse.urlparse(self.API_RUL).hostname
        host_name = host_name.lower()
        paramsPrefix = {"host": host_name, 'method': method, 'uri': '/v1/' + API_URI}
        params_to_sign.update(params)
        params_to_sign['Signature'] = self.paramsSign(params_to_sign, paramsPrefix, self.secret).decode(
            encoding='UTF-8')
        url = self.API_RUL + API_URI
        try:
            if method == 'GET':
                return http_get_request(url, params_to_sign, 10)
            elif method == 'POST':
                return http_post_request(url, params_to_sign, 10)
        except requests.exceptions.HTTPError as err:
            print(err)
            print('request error')

    def get_depth(self):
        """get market depth"""
        return self.public_request('GET', 'depth', symbol=self.symbol)

    def get_account_info(self):
        """get account info(done)"""
        return self.api_key_request('GET', 'balance')

    def create_order(self, **payload):
        """create order(done)"""
        return self.api_key_request('POST', 'order/place', **payload)

    def trade(self, price, amount, direction):
        """trade someting, buy(1) or sell(0)"""
        try:
            if direction == 1:
                return self.buy(price, amount)
            else:
                return self.sell(price, amount)
        except Exception as e:
            print(e)
            print("Trade error")
            return "Trade error"

    def buy(self, price, amount):
        """buy someting(done)"""
        return self.create_order(symbol=self.symbol, type='buy', tradePrice=price, tradeAmount=amount)

    def sell(self, price, amount):
        """sell someting(done)"""
        return self.create_order(symbol=self.symbol, type='sell', tradePrice=price, tradeAmount=amount)

    # def get_order(self, order_id):
    #     """get specfic order(done)"""
    #     return self.signed_request('GET', 'order', orderId=order_id, symbol=self.symbol)

    def get_open_order(self):
        """get specfic order(done)"""
        return self.api_key_request('GET', 'order/entrust', symbol=self.symbol, tpye=1, count=100)

    # def create_order_test(self):
    #     """get specfic order(done)"""
    #     # {"symbol":"BTCUSDT","price":"9300","volume":"1","side":"BUY","type":"LIMIT"} Copied!
    #     return self.signed_request('GET', 'order/test', symbol=self.symbol, volume=1, side="BUY", type="LIMIT",
    #                                price=9300)

    def cancel_order(self, order_id):
        """cancel specfic order(done)"""
        return self.api_key_request('POST', 'order/cancel', id=order_id)


if __name__ == "__main__":
    print("Start...")
    hot_coin = HotCoin(symbol="apg_usdt")
    print(hot_coin.get_depth())
