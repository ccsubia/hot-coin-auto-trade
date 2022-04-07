# -*- coding:UTF-8 -*-
#!/usr/bin/env python

import time
import json
import random
import asyncio
import zlib
import os
import re
import datetime
from collections import namedtuple
import traceback

import pandas as pd
import websockets

import logging
logging.basicConfig(level=logging.INFO,
                    format = '%(asctime)s - %(levelname)s - %(message)s')

from vaex_api import CancelRecord
from default_config import config
import utils

# websocket接口
async def get_dpeth(websocket):
    # reqParam = DEPTH_PARAM
    # await websocket.send(reqParam)
    recv_text = await websocket.recv()
    ret = zlib.decompress(recv_text, 16 + zlib.MAX_WBITS).decode('utf-8')
    ret = json.loads(ret)
    sellprice, sellvolume = [], []
    buyprice, buyvolume = [], []
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
#     DepthData = vaex.get_depth(limit=level)
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

# self trade
#self交易量的区间和频率： 在买一卖一随机取价和区间，两秒后进行撤销
async def self_trade(vaex, websocket):
    reqParam = config['depth_param']
    await websocket.send(reqParam)
    self_cnt = 0
    while True:
        try:
            print_prefix = f'[Self Trade: {self_cnt}]'
            logging.info(f'{print_prefix} Start time {utils.get_now_time_str("%Y/%m/%d %H:%M:%S")}...')
            buyprice, buyvolume, sellprice, sellvolume = await get_dpeth(websocket)
            if not buyprice or not sellprice:
                logging.warning(f"{print_prefix} get depth failed, retry")
                continue
            direction = random.randint(0, 1)
            side_str = '买单' if direction else '卖单'
            tradeprice = round(random.uniform(float(buyprice[0]), float(sellprice[0])), config['price_decimal_num'])
            tradeVolume = round(random.uniform(config['self_tradeMin'], config['self_tradeMax']), config['volumn_decimal_num'])
            '''if self_trade_price_max!=0 and tradeprice > self_trade_price_max:
                tradeprice = self_trade_price_max
            if self_trade_price_min!=0 and tradeprice < self_trade_price_min:
                tradeprice = self_trade_price_min'''
            result = vaex.trade(price=tradeprice, amount=tradeVolume, direction=direction)
            if vaex.check_trade_status(result):
                logging.info(f'{print_prefix} 下单方向:{side_str}, 价格:{tradeprice}, 下单量:{tradeVolume}')
                time.sleep(config['self_tradeFrequence']) # n秒后进行反向下单
                result = vaex.trade(price=tradeprice, amount=tradeVolume, direction=1-direction)
                #打印结果值
                if vaex.check_trade_status(result):
                    logging.info(f'{print_prefix} 反向下单成功')
                else:
                    logging.warning(f'{print_prefix} 反向下单失败')
            else:
                logging.warning(f'{print_prefix} 下单失败, retry')
                time.sleep(2)
        except Exception as e:
            traceback.print_exc()
            time.sleep(2)
        self_cnt += 1

# cross trade
#在买一和买十，卖一和卖十之间随机取价和区间，每6秒下单一次
async def cross_trade(vaex, websocket):
    reqParam = config['depth_param']
    await websocket.send(reqParam)
    cross_cnt = 0
    while True:
        try:
            print_prefix = f'[Cross Trade: {cross_cnt}]'
            logging.info(f'{print_prefix} Start time {utils.get_now_time_str("%Y/%m/%d %H:%M:%S")}...')
            buyprice, buyvolume, sellprice, sellvolume = await get_dpeth(websocket)
            if not buyprice or not sellprice:
                logging.warning(f"{print_prefix} get depth failed, retry")
                continue
            #在买一和买十，卖一和卖十之间随机取价和区间
            direction = random.randint(0, 1) #随机取方向
            side_str = '买单' if direction else '卖单'
            if direction: #如果随机数为1，挂买单
                if len(buyprice) > config['cross_depth']:
                    tradeprice = round(random.uniform(float(buyprice[9]), float(buyprice[0])), config['price_decimal_num']) #随机取价格
                    tradeVolume = round(random.uniform(config['cross_tradeMin'], config['cross_tradeMax']), config['volumn_decimal_num']) #随机取量
                else:
                    tradeprice = round(random.uniform(float(buyprice[-1]), float(buyprice[0])), config['price_decimal_num'])
                    tradeVolume = round(random.uniform(config['cross_tradeMin'], config['cross_tradeMax']), config['volumn_decimal_num'])
            else:
                if len(sellprice) > config['cross_depth']:
                    tradeprice = round(random.uniform(float(sellprice[0]), float(sellprice[9])), config['price_decimal_num'])
                    tradeVolume = round(random.uniform(config['cross_tradeMin'], config['cross_tradeMax']), config['volumn_decimal_num'])
                else:
                    tradeprice = round(random.uniform(float(sellprice[0]), float(sellprice[-1])), config['price_decimal_num'])
                    tradeVolume = round(random.uniform(config['cross_tradeMin'], config['cross_tradeMax']), config['volumn_decimal_num'])

            if config['cross_trade_price_max']!=0 and tradeprice > config['cross_trade_price_max']:
                tradeprice = config['cross_trade_price_max']
            if config['cross_trade_price_min']!=0 and tradeprice < config['cross_trade_price_min']:
                tradeprice = config['cross_trade_price_min']
            result = vaex.trade(price=tradeprice, amount=tradeVolume, direction=direction)
            if vaex.check_trade_status(result):
                logging.info(f'{print_prefix} 下单方向:{side_str}, 价格:{tradeprice}, 下单量:{tradeVolume}')
            else:
                logging.warning(f'{print_prefix} 下单失败, retry')
                time.sleep(2)
                continue
            time.sleep(config['cross_tradeFrequence'])
        except Exception as e:
            traceback.print_exc()
            time.sleep(2)
        cross_cnt += 1

# cancel trade
def adjustable_cancel(vaex):
    now = utils.get_now_time_str()
    output_fpath = os.path.join(config['cancel_data_dir'], now)
    # dir
    if not os.path.isdir(config['cancel_data_dir']):
        os.makedirs(config['cancel_data_dir'])
    f_out = open(output_fpath, 'a')
    record_cnt = 0
    cancel_cnt = 0
    interval = config['cancel_adjustable_time']
    while True:
        print_prefix = f'[Cancel: {cancel_cnt}]'
        logging.info(f'{print_prefix} Start time {utils.get_now_time_str("%Y/%m/%d %H:%M:%S")}...')
        result = vaex.get_open_order()
        if 'data' in result and 'entrutsCur' in result['data'] and len(result['data']['entrutsCur']) > 0:
            order_list = result['data']['entrutsCur']
            index = random.randint(0, len(order_list) - 1)
            result = vaex.cancel_order(order_list[index]['id'])
            if result['code'] == 200:
                # order_info = vaex.get_order(order_id=order_list[index]['id'])
                order_info = order_list[index]
                # logging.info(f'{print_prefix} {order_info}')
                # if order_info['status'] == '已撤销':
                # cancal successful
                interval = 12 * config['cancel_adjustable_time'] / len(order_list)
                logging.info(f"{print_prefix} 撤销订单: {order_list[index]['id']}, " \
                             f"types: {order_info['types']}, price: {order_info['price']}, " \
                             f"'count': {float(order_info['count'])-float(order_info['leftcount'])}" \
                             f", 委托单个数: {len(order_list)}, 撤单间隔: {round(interval,2)}s")
                cancel_record = CancelRecord(
                    order_info['id'],
                    order_info['types'],
                    order_info['price'],
                    order_info['count'],
                    order_info['leftcount'],
                    utils.get_now_time_str(),
                    )
                f_out.write('\t'.join([str(it) for it in list(cancel_record)]) + '\n')
                record_cnt += 1
                record_max_num = 1000
                if config['debug']:
                    record_max_num = 10
                if record_cnt > record_max_num:
                    f_out.close()
                    # clear old file
                    filelist = os.listdir(config['cancel_data_dir'])
                    if len(filelist) > config['save_file_num']:
                        filelist.sort(reverse=True)
                        for name in filelist[config['save_file_num']:]:
                            delete_path = os.path.join(config['cancel_data_dir'], name)
                            os.remove(delete_path)
                    # new file name
                    min = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
                    output_fpath = os.path.join(config['cancel_data_dir'], min)
                    f_out = open(output_fpath, 'a')
                    record_cnt = 0
            time.sleep(interval)  # 120s/每次撤单的延时时间为未成交单量,相当于恒定未成交单量的速度下，两分钟可以撤销完
        else:
            logging.info(f"{print_prefix} find no open order, continue")
            time.sleep(config['cancel_adjustable_time'])
        cancel_cnt += 1

# 获取交易订单信息
def save_trades(vaex, output_dir, save_file_num=1000):    
    output_fpath = utils.get_new_filename(output_dir, save_file_num=save_file_num)
    # get data
    TradeRecord = namedtuple('TradeRecord', ['id', 'side', 'price', 'qty', 'time'])
    def parse_my_trade(input_trades):
        trade_res = []
        try:
            for trade_info in input_trades['data']:
                trade_res.append(TradeRecord(
                    trade_info['id'],
                    trade_info['type'],
                    trade_info['price'],
                    trade_info['filledAmount'],
                    utils.unix_ms_to_str(float(trade_info['createdAt'])),
                ))
        except Exception as e:
            traceback.print_exc()
        return trade_res
    trade_ret = parse_my_trade(vaex.get_my_trade())
    trade_ret = pd.DataFrame(trade_ret)
    trade_ret.to_csv(output_fpath, header=True)
    logging.info(f"[save Trade] Successfully save trades: {output_fpath}")

def print_trade_report(input_dir, output_dir, start_time=0, end_time=0):
    filelist = os.listdir(input_dir)
    all_data = []
    for name in filelist:
        fpath = os.path.join(input_dir, name)
        all_data.append(pd.read_csv(fpath, index_col=0))
    if not all_data:
        logging.warning("[Trade Report] No data, wait for next time period")
        return
    all_data = pd.concat(all_data).drop_duplicates()
    if start_time:
        all_data = all_data[all_data['time'] >= int(start_time)]
    if end_time:
        all_data = all_data[all_data['time'] <= int(end_time)]
    if all_data.empty:
        logging.info("[Trade report] No valid data, wait for next time period")
        return
    def f(x):
        d = {}
        d['count'] = x['id'].count()
        d['sum_qty'] = x['qty'].sum()
        d['avg_price'] = (x['qty'] * x['price']).sum() / x['qty'].sum()
        d['sum_price'] = (x['qty'] * x['price']).sum()
        return pd.Series(d, index=['count', 'sum_qty', 'avg_price', 'sum_price'])
    group_res = all_data.groupby("side").apply(f)
    group_res['start_time'] = [utils.get_readable_time(start_time)] * group_res.shape[0]
    group_res['end_time'] = [utils.get_readable_time(end_time)] * group_res.shape[0]
    group_res = group_res.reset_index()
    group_res.columns = ['方向', '成交笔数', '成交数量', '成交均价', '成交金额', '统计开始时间', '统计结束时间']
    group_res = group_res.round(5)
    utils.print_dataframe(group_res)
    group_res.to_csv(f"{utils.get_new_filename(output_dir, save_file_num=1000, name_format='%Y%m%d')}_trade.csv")
        
def print_cancel_report(input_dir, output_dir, start_time=0, end_time=0):
    if not os.path.isdir(input_dir):
        logging.info("[Cancel report] No data, wait for next time period")
        return
    filelist = os.listdir(input_dir)
    all_data = []
    for name in filelist:
        fpath = os.path.join(input_dir, name)
        all_data.append(pd.read_csv(fpath, sep='\t', names=list(CancelRecord._fields), encoding='unicode_escape'))
    all_data = pd.concat(all_data).drop_duplicates()
    if start_time:
        all_data = all_data[all_data['time'] >= int(start_time)]
    if end_time:
        all_data = all_data[all_data['time'] <= int(end_time)]
    if all_data.empty:
        logging.info("[Cancel report] No valid data, wait for next time period")
        return
    def f(x):
        d = {}
        d['count'] = x['orderId'].count()
        d['sum_qty'] = (x['origQty'] - x['executedQty']).sum()
        d['avg_price'] = ((x['origQty'] - x['executedQty']) * x['price']).sum() / (x['origQty'] - x['executedQty']).sum()
        d['sum_price'] = ((x['origQty'] - x['executedQty']) * x['price']).sum()
        return pd.Series(d, index=['count', 'sum_qty', 'avg_price', 'sum_price'])
    group_res = all_data.groupby("side").apply(f)
    group_res['start_time'] = [utils.get_readable_time(start_time)] * group_res.shape[0]
    group_res['end_time'] = [utils.get_readable_time(end_time)] * group_res.shape[0]
    group_res = group_res.reset_index()
    group_res.columns = ['方向', '撤单笔数', '撤单数量', '撤单均价', '撤单金额', '统计开始时间', '统计结束时间']
    group_res = group_res.round(5)
    utils.print_dataframe(group_res)
    group_res.to_csv(f"{utils.get_new_filename(output_dir, save_file_num=1000, name_format='%Y%m%d')}_cancel.csv")

# 波动交易
def target_trade_action(vaex, adjusted_percent: float):
    if adjusted_percent > 0:
        depth_direction = 'asks'
        trade_direction = 1
        trade_direction_str = 'buy'
    else:
        depth_direction = 'bids'
        trade_direction = 0
        trade_direction_str = 'sell'
    depth_info_list = vaex.get_depth_list(depth_direction)
    if depth_info_list:
        start_price = depth_info_list[0][0]
        target_price = start_price * (1+adjusted_percent)
        for single_depth in depth_info_list:
            price, volumn = single_depth
            if float(price) <= target_price:
                # logging.info(f'[Target Trade] current_price:{start_price}, target_price:{target_price}'
                #              f', trade_direction:{trade_direction_str}, trade_price:{price}, trade_volumn:{volumn}')
                # time.sleep(0.5)
                trade_ret = vaex.trade(price, volumn, trade_direction)
                if vaex.check_trade_status(trade_ret):
                    logging.info(f'[Target Trade] current_price:{start_price}, target_price:{target_price}'
                                 f', trade_direction:{trade_direction_str}, trade_price:{price}, trade_volumn:{volumn}')
                time.sleep(0.5)
        depth_info_list = vaex.get_depth_list(depth_direction)
        current_price = depth_info_list[0][0]
        finish_rate = (current_price - start_price) / (target_price - start_price)
        logging.info(f'Finish rate: {finish_rate}, start_price: {start_price}, current_price: {current_price}')
    else:
        logging.warning("No depth data")
        return

def target_trade_allocation(vaex, adjust_percent, duration_min, action_num):
    try:
        adjust_percent_list = utils.random_split(adjust_percent, action_num, 10000)
        if duration_min == 0:
            duration_second_list = [0] * action_num
        else:
            duration_second_list = utils.random_split(duration_min * 60, action_num, 1)
        # print(adjust_percent_list)
        # print(duration_second_list)
        for i in range(action_num):
            time.sleep(duration_second_list[i])
            target_trade_action(vaex, adjust_percent_list[i])
    except Exception as e:
        traceback.print_exc()




# async func
def func(target_func):
    while True:
        try:
            logging.info("Start main func...")
            async def main_logic():
                async with websockets.connect(config['web_addr'], ping_interval=None) as websocket:
                    await target_func(websocket)
            asyncio.get_event_loop().run_until_complete(main_logic())
        except Exception as e:
            traceback.print_exc()
            logging.warninga("Main func failed, restart")

