# -*- coding:UTF-8 -*-
# !/usr/bin/env python

from hot_coin_api import HotCoin
import time
import json
import random
import datetime
import asyncio
import websockets
import zlib
import multiprocessing

SYMBOL = "apg_usdt"
DEPTH_PARAM = '{"sub":"market.apg_usdt.trade.depth"}'
ADDR = "wss://wss.hotcoinfin.com/trade/multiple"
hot_coin = HotCoin(symbol=SYMBOL)

# 请在这里配置api key和api secret
hot_coin.auth(key="", secret="")


# websocket接口
async def get_dpeth(websocket):
    # reqParam = DEPTH_PARAM
    # await websocket.send(reqParam)
    recv_text = await websocket.recv()
    ret = zlib.decompress(recv_text, 16 + zlib.MAX_WBITS).decode('utf-8')
    ret = json.loads(ret)
    sellprice, sellvolume = [], []
    buyprice, buyvolume = [], []
    if 'ping' in ret:
        await websocket.send('{"pong": "pong"}')
        recv_text = await websocket.recv()
        ret = zlib.decompress(recv_text, 16 + zlib.MAX_WBITS).decode('utf-8')
        ret = json.loads(ret)
    if 'data' in ret:
        depth_data = ret['data']
        if ('asks' in depth_data) and ('bids' in depth_data):
            for order in depth_data['asks']:
                sellprice.append(order[0])
                sellvolume.append(order[1])
            for order in depth_data['bids']:
                buyprice.append(order[0])
                buyvolume.append(order[1])
    # 分别获得买的挂单价格序列buyprice，买的挂单量序列buyvolume，卖的挂单价格序列sellprice，卖的挂单量序列sellvolume
    return buyprice, buyvolume, sellprice, sellvolume


# api接口
# # 分别获得买的挂单价格序列buyprice，买的挂单量序列buyvolume，卖的挂单价格序列sellprice，卖的挂单量序列sellvolume
# #  return buyprice, buyvolume, sellprice, sellvolume
# def getDepth(level = 100):
#     # 获取L20,L100,full 水平的深度盘口数据
#     DepthData = hot_coin.get_depth(limit=level)
#     # 分离出买卖价格序列和买卖量的序列
#     sellprice, sellvolume = [], []
#     buyprice, buyvolume = [], []
#     if ('asks' in DepthData) and ('bids' in DepthData):
#         for order in DepthData['asks']:
#             sellprice.append(order[0])
#             sellvolume.append(order[1])
#         for order in DepthData['bids']:
#             buyprice.append(order[0])
#             buyvolume.append(order[1])
#     # 分别获得买的挂单价格序列buyprice，买的挂单量序列buyvolume，卖的挂单价格序列sellprice，卖的挂单量序列sellvolume
#     return buyprice, buyvolume, sellprice, sellvolume

# self交易量的区间和频率： 在买一卖一随机取价和区间，两秒后进行撤销
async def self_trade(websocket):
    reqParam = DEPTH_PARAM
    await websocket.send(reqParam)
    while True:
        try:
            print(f'Start self trade {datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")}...')
            # print('1self_trade')
            try:
                buyprice, buyvolume, sellprice, sellvolume = await get_dpeth(websocket)
            except Exception as e:
                print(e)
                print("Self get depth exception, break.")
                break
            # print(buyprice, buyvolume, sellprice, sellvolume)
            # print('self_trade')
            if not buyprice or not sellprice:
                print("Self get depth failed")
                continue
            direction = random.randint(0, 1)
            tradeprice = round(random.uniform(float(buyprice[0]), float(sellprice[0])), 4)
            tradeVolume = round(random.uniform(self_tradeMin, self_tradeMax), 1)
            '''if self_trade_price_max!=0 and tradeprice > self_trade_price_max:
                tradeprice = self_trade_price_max
            if self_trade_price_min!=0 and tradeprice < self_trade_price_min:
                tradeprice = self_trade_price_min'''
            result = hot_coin.trade(price=tradeprice, amount=tradeVolume, direction=direction)
            if 'code' in result and result['code'] == 200:
                print('\nself交易  价格' + str(tradeprice) + '  ' + datetime.datetime.now().strftime(
                    "%Y/%m/%d %H:%M:%S") + ' 下单量' + str(tradeVolume))
                time.sleep(self_tradeFrequence)  # 两秒后进行反向交易
                result = hot_coin.trade(price=tradeprice, amount=tradeVolume, direction=1 - direction)
                print('fx', 1 - direction, result)
                # 打印结果值
                if 'code' in result and result['code'] == 200:
                    if direction:
                        print('self交易:  self卖回成功')
                    else:
                        print('self交易:  self买回成功')
                else:
                    if direction:
                        print('self交易:  self卖回失败')
                    else:
                        print('self交易:  self买回失败')
            else:
                print("Self trade fail....")
                time.sleep(1)
        except Exception as e:
            print(e)
            print("Self trade exception, break")
            time.sleep(1)
            break


# 在买一和买十，卖一和卖十之间随机取价和区间，每6秒下单一次
async def addentrust(websocket):
    reqParam = DEPTH_PARAM
    await websocket.send(reqParam)
    while True:
        try:
            print(f'Start cross trade {datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")}...')
            try:
                buyprice, buyvolume, sellprice, sellvolume = await get_dpeth(websocket)
            except Exception as e:
                print(e)
                print("Cross get depth exception, break.")
                time.sleep(1)
                break
            # print(buyprice, buyvolume, sellprice, sellvolume)
            if not buyprice or not sellprice:
                print("Cross get depth failed, retry")
                continue
            else:
                print("Cross get depth success...")
            # 在买一和买十，卖一和卖十之间随机取价和区间
            direction = random.randint(0, 1)  # 随机取方向
            flagDirec = ""
            if direction:  # 如果随机数为1，挂买单
                if len(buyprice) > 10:
                    tradeprice = round(random.uniform(float(buyprice[9]), float(buyprice[0])), 4)  # 随机取价格
                    tradeVolume = round(random.uniform(cross_tradeMin, cross_tradeMax), 1)  # 随机取量
                else:
                    tradeprice = round(random.uniform(float(buyprice[-1]), float(buyprice[0])), 4)
                    tradeVolume = round(random.uniform(cross_tradeMin, cross_tradeMax), 1)
                flagDirec = '买'
            else:
                if len(sellprice) > 10:
                    tradeprice = round(random.uniform(float(sellprice[0]), float(sellprice[9])), 4)
                    tradeVolume = round(random.uniform(cross_tradeMin, cross_tradeMax), 1)
                else:
                    tradeprice = round(random.uniform(float(sellprice[0]), float(sellprice[-1])), 4)
                    tradeVolume = round(random.uniform(cross_tradeMin, cross_tradeMax), 1)
                flagDirec = '卖'

            if cross_trade_price_max != 0 and tradeprice > cross_trade_price_max:
                tradeprice = cross_trade_price_max
            if cross_trade_price_min != 0 and tradeprice < cross_trade_price_min:
                tradeprice = cross_trade_price_min
            result = hot_coin.trade(price=tradeprice, amount=tradeVolume, direction=direction)
            if 'code' in result and result['code'] == 200:
                print(
                    '\ncross交易订单:  价格' + str(tradeprice) + '  ' + datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                    + ' 下单量' + str(tradeVolume) + ' 方向:' + flagDirec)
            else:
                print("Cross trade fail")
            time.sleep(cross_tradeFrequence)
        except Exception as e:
            print(e)
            print("Cross exception, break")
            time.sleep(1)
            break


# 延迟一分钟后，陆续撤单（撤单顺序随机）
def adjustable_cancel():
    # time.sleep(30)
    while True:
        try:
            result = hot_coin.get_open_order()
            if 'data' in result and 'entrutsCur' in result['data'] and len(result['data']['entrutsCur']) > 0:
                order_list = result['data']['entrutsCur']
                index = random.randint(0, len(order_list) - 1)
                result = hot_coin.cancel_order(order_list[index]['id'])
                if 'code' in result and result['code'] == 200:
                    interval = 12 * adjustable_time / len(order_list)
                    print('撤销订单:' + str(order_list[index]['id']) + '  委托单个数：' + str(len(order_list)) + ' 撤单间隔：' + str(
                        round(interval, 2)) + 's')
                time.sleep(interval)  # 120s/每次撤单的延时时间为未成交单量,相当于恒定未成交单量的速度下，两分钟可以撤销完
        except Exception as e:
            print(e)
            print("Cancel exception, continue")
            time.sleep(1)


# 撤单时间间隔，越小越快
adjustable_time = 30

# self交易量的区间和频率： 在买一卖一随机取价和区间，n秒后进行反向操作
self_tradeFrequence = 10  # 5秒后反向交易，这个值越小交易越快
self_tradeMin = 98
self_tradeMax = 100
# cross交易量的区间和频率： 在买一和买十，卖一和卖十之间随机取价和区间，每n秒下单一次
cross_tradeFrequence = 15  # 这个值越小交易越快
cross_tradeMin = 10
cross_tradeMax = 40
# 新增：cross交易价格的上下限时，为0表示不设置
cross_trade_price_max = 0.2352
cross_trade_price_min = 0.2185


def func(target_func):
    # while True:
    try:
        print("Start main func...")

        async def main_logic():
            async with websockets.connect(ADDR, ping_interval=None) as websocket:
                await target_func(websocket)

        asyncio.get_event_loop().run_until_complete(main_logic())
    except Exception as e:
        print(e)
        print("main func failed, restart")


if __name__ == "__main__":
    pool = multiprocessing.Pool(processes=3)
    pool.apply_async(func, (self_trade,))
    pool.apply_async(func, (addentrust,))
    pool.apply_async(adjustable_cancel)
    # pool.apply_async(func, (test_depth,))
    pool.close()
    pool.join()
