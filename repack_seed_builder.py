# -*- coding: utf-8 -*-
import datetime
import shutil

__author__ = 'Joshua Zhang'
import os
import operator
import json
import logging
import sys
#import Levenshtein

import MySQLdb

from Utils import Timeout
from Utils.ByteOperation import GetSha1ByBytes
from Utils import Logger


reload(sys)
sys.setdefaultencoding('utf-8')

logger = Logger.init_log("repack_seed_builder.log", logging.getLogger(__name__))

STR_FROM = "AllofCNMARSTeam@dl.trendmicro.com"
#STR_TO = ["AllofCNMARSResearchTeam@dl.trendmicro.com",
# "AllofCNMobileOpsTeam@dl.trendmicro.com"]
STR_TO = ["joshua_zhang@trendmicro.com.cn"]

with open('config.json', 'r') as f:
    config = json.load(f)


CLOUD_DB_USER = config['CLOUD_DB_USER']
CLOUD_DB_PASSWD = config['CLOUD_DB_PASSWD']
CLOUD_DB_HOST = config['CLOUD_DB_HOST']
CLOUD_DB_NAME = config['CLOUD_DB_NAME']

GLOBAL_DB_USER = config['GLOBAL_DB_USER']
GLOBAL_DB_PASSWD = config['GLOBAL_DB_PASSWD']
GLOBAL_DB_HOST = config['GLOBAL_DB_HOST']
GLOBAL_DB_NAME = config['GLOBAL_DB_NAME']

STR_LENGTH = 192


def connect(user, pwd, host, db):
    try:
        conn = MySQLdb.connect(user=user, passwd=pwd, host=host, db=db, charset='utf8')
    except Exception, e:
        logger.error("connect database error: %s" % e)
        raise Exception("connect database error")
    return conn


def cal_sha1(apk_path, logger):
    resCode = None
    implFolder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "APKS/")
    parseCmd = 'sha256sum %s' % apk_path
    timeout = 30 * 1000
    resList = Timeout.CommandTimeOut(parseCmd, timeout, ' ', logger, True, implFolder)
    for line in resList:
        if len(line) >= 64:
            resCode = line.split('  ')[0].strip()
            break
    return resCode


def move_apks(act, sourcing, str_time):
    apk_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "APKS/")
    if act == 'add':
        backup_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ADD_BACKUP/")
    elif act == 'del':
        backup_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "DEL_BACKUP/")
    sub_backup_folder = sourcing + '_' + str_time
    fin_backup_folder = os.path.join(backup_folder, sub_backup_folder)
    if os.listdir(apk_folder) != '':
        shutil.move(apk_folder, fin_backup_folder)
    if not os.path.exists('APKS/'):
        os.makedirs('APKS/')


def modify_threshold(seed, dis_threshold):
    seed_len = len(seed.decode("utf-8"))
    if seed_len <= 3:
        dis_threshold -= 2
    elif seed_len == 4:
        dis_threshold -= 1
    if dis_threshold < 0:
        return 0
    return dis_threshold


def get_label_rate(seed_tuple, app_label, publickey):
    l = []

    for item in seed_tuple:
        (byte_sha1, icon_hash, is_original, repack_from, seed_label, publickey_sha1list, c_sha1) = item

        if isinstance(app_label, unicode):
            app_label = app_label.encode('utf8', 'ignore')
        if isinstance(seed_label, unicode):
            seed_label = seed_label.encode('utf8', 'ignore')
        distance = Levenshtein.distance(str(app_label), str(seed_label))
        mod_threshold = 6
        label_rate = 0
        if distance <= mod_threshold:
            label_rate = int((float(mod_threshold - distance) / float(mod_threshold)) * 100)
        if label_rate >= 100:
            label_rate = 0
        if publickey_sha1list != publickey and label_rate >= 65:
            l.append(
                [byte_sha1, icon_hash, is_original, repack_from, seed_label, publickey_sha1list, label_rate, c_sha1])
    sorted_list = sorted(l, key=operator.itemgetter(6), reverse=True)
    return sorted_list[0:1000]


def cal_icon_hash(apk_path, logger):
    resCode = None
    implFolder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "")
    parseCmd = 'nohup java -jar ./lib/IconSim.jar %s' % apk_path
    timeout = 30 * 1000
    resList = Timeout.CommandTimeOut(parseCmd, timeout, ' ', logger, True, implFolder)
    for line in resList:
        if line.find('IconHash:') != -1:
            resCode = line.split('IconHash:')[-1].strip()
            break
    return resCode


def compare_icon_hash(hash1, hash2):
    try:
        if long(hash1, 16) == 0:
            return 0
    except Exception, e:
        logger.error("compare icon error: %s" % e)
    try:
        if long(hash2, 16) == 0:
            return 0
    except Exception, e:
        logger.error("compare icon error: %s" % e)

    hash1 = hash1.zfill(STR_LENGTH)
    hash2 = hash2.zfill(STR_LENGTH)
    diffCount = 0
    for i in range(STR_LENGTH):
        val1 = int(hash1[i:i + 1], 16)
        val2 = int(hash2[i:i + 1], 16)
        diffCount += abs(val1 - val2)

    score = (STR_LENGTH * 15 - diffCount) * 100.0 / STR_LENGTH / 15
    result = int(round(score * score / 100))
    # logger.debug(("compare: " + hash1[0:9] + " " + hash2[0:9] + " : " + str(result)))
    return result


def get_app_label(conn, sha1):
    try:
        cursor = conn.cursor()
        sql_line = ("select label from apk_mars_detection where Sha256 = 0x%s" % sha1)
        cursor.execute(sql_line)
        res = cursor.fetchone()
        if res:
            return res[0]
        else:
            return None
    except Exception, e:
        logger.error("query DB error, %s" % e)


def query_pkg_name(conn, sha1):
    try:
        cursor = conn.cursor()
        sql_line = ("select packageName from apk_mars_detection where Sha256 = 0x%s" % sha1)
        cursor.execute(sql_line)
        res = cursor.fetchone()
        if res:
            return res[0]
        else:
            return None
    except Exception, e:
        logger.error("query DB error, %s" % e)


def query_public_key(conn, sha1):
    try:
        cursor = conn.cursor()
        sql_line = ("select hex(publicKeySha1) from apk_mars_detection where Sha256 = 0x%s" % sha1)
        cursor.execute(sql_line)
        res = cursor.fetchone()
        if res:
            return res[0]
        else:
            return None
    except Exception, e:
        logger.error("query DB error, %s" % e)


def query_repack_info(conn):
    try:
        cursor = conn.cursor()
        sql_line = ("SELECT r.Sha1, r.IconHash, r.IsOriginal, r.RepackFrom, a.AppLabel, a.PublicKeySha1List, a.Sha1 "
                    "FROM ApkRepackINFO r RIGHT JOIN AppInfo a ON r.Sha1 = a.Sha1 AND r.IconHash != '0' LIMIT 2000000")
        cursor.execute(sql_line)
        res = cursor.fetchall()
        if res:
            return res
        else:
            return None
    except Exception, e:
        logger.error("query DB error, %s" % e)


def gen_sha1_list(candidate_list):
    fl = open('_sha1_list.txt', 'a')
    sha1_items = ''
    logger.info('Generating Sha1 List:')
    for item in candidate_list:
        byte_sha1 = item[0]
        if byte_sha1:
            sha1_items += GetSha1ByBytes(item[7]) + '\n'
            print sha1_items,
    fl.writelines(sha1_items)
    fl.close()


def query_applabel(conn,sha256):
    cursor = conn.cursor()
    sql_line = ("SELECT label_ja, label_zhCN, label_zhTW FROM apk_label_info WHERE sha256 = 0x%s"  %  sha256)
    cursor.execute(sql_line)
    row = cursor.fetchone()
    logger.debug(row)
    if row:
        return row
    else:
        return (None,None,None)
    


def insert_seed(conn, PublicKeySha1List, PkgName, RepackStrategy, LabelWeight, IconWeight, JudgmentMethod, RepackThreshold, ExFeature3, ExFeature4):
    cursor = conn.cursor()
    if ExFeature4 is None:
        sql_line = ("INSERT INTO apk_repack_seed ("
                    "publicKeySha1, packageName, RepackStrategy, LabelWeight, IconWeight, JudgmentMethod, RepackThreshold, submitter, submitTime) "
                    "VALUES (0x%s, '%s', %s, %s, %s, %s, %s, '%s', NULL)" % (
                        PublicKeySha1List, PkgName, RepackStrategy, LabelWeight, IconWeight, JudgmentMethod, RepackThreshold, ExFeature3))
    else:
        sql_line = ("INSERT INTO apk_repack_seed ("
                    "publicKeySha1, packageName, RepackStrategy, LabelWeight, IconWeight, JudgmentMethod, RepackThreshold, submitter, Category, submitTime) "
                    "VALUES (0x%s, '%s', %s, %s, %s, %s, %s, '%s', 1, '%s')" % (
                        PublicKeySha1List, PkgName, RepackStrategy, LabelWeight, IconWeight, JudgmentMethod, RepackThreshold, ExFeature3, ExFeature4))

    try:
        logger.info("Insert seed: %s" % sql_line)
        cursor.execute(sql_line)
        r = conn.commit()
        print r
    except Exception, e:
        logger.error(e)


def check_seed_id(conn, PublicKeySha1List, PkgName):
    cursor = conn.cursor()
    sql_line = ("SELECT seedId "
                "FROM apk_repack_seed "
                "WHERE publicKeySha1 = 0x%s AND packageName = '%s' " % (PublicKeySha1List, PkgName))
    try:
        cursor.execute(sql_line)
        row = cursor.fetchone()
        SeedID = row[0]
        logger.info("SeedID: %s PublicKeySha1List: %s PkgName: %s" % (SeedID, PublicKeySha1List, PkgName))
        return SeedID
    except Exception, e:
        logger.error(e)


def insert_icon(conn, SeedID, IconHash):
    cursor = conn.cursor()
    check_line = ("SELECT * FROM apk_repack_seed_icon_hash WHERE IconHash = %s AND SeedID = %s")
    try:
        cursor.execute(check_line, (IconHash, SeedID))
        is_exist = cursor.fetchone()
        logger.debug('icon is exist:' + str(is_exist))
    except Exception, e:
        logger.error(e)
    if not is_exist:
        sql_line = ("INSERT INTO apk_repack_seed_icon_hash ("
                    "SeedID, IconHash) "
                    "VALUES (%s, '%s')" % (SeedID, IconHash))
        try:
            cursor.execute(sql_line)
            conn.commit()
        except Exception, e:
            logger.error(e)


def insert_label(conn, SeedID, AppLabel, AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW):
    cursor = conn.cursor()
    if not AppLabel_ja and not AppLabel_zhCN and not AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja IS %s "
                    "AND AppLabel_zhCN IS  %s "
                    "AND AppLabel_zhTW IS %s")
    if not AppLabel_ja and not AppLabel_zhCN and AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja IS %s "
                    "AND AppLabel_zhCN IS  %s "
                    "AND AppLabel_zhTW = %s")
    if not AppLabel_ja and AppLabel_zhCN and not AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja IS %s "
                    "AND AppLabel_zhCN =  %s "
                    "AND AppLabel_zhTW IS %s")
    if not AppLabel_ja and AppLabel_zhCN and AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja IS %s "
                    "AND AppLabel_zhCN = %s "
                    "AND AppLabel_zhTW = %s")
    if AppLabel_ja and not AppLabel_zhCN and not AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja = %s "
                    "AND AppLabel_zhCN IS  %s "
                    "AND AppLabel_zhTW IS %s")
    if AppLabel_ja and not AppLabel_zhCN and AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja = %s "
                    "AND AppLabel_zhCN IS  %s "
                    "AND AppLabel_zhTW = %s")

    if AppLabel_ja and AppLabel_zhCN and not AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja = %s "
                    "AND AppLabel_zhCN = %s "
                    "AND AppLabel_zhTW IS %s")

    if AppLabel_ja and AppLabel_zhCN and AppLabel_zhTW:
        check_line = ("SELECT * FROM apk_repack_seed_app_label "
                    "WHERE SeedID = %s "
                    "AND AppLabel = %s "
                    "AND AppLabel_ja = %s "
                    "AND AppLabel_zhCN = %s "
                    "AND AppLabel_zhTW = %s")
    try:
        cursor.execute(check_line, (SeedID, AppLabel, AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW))
        is_exist = cursor.fetchone()

        sql_line = ("INSERT INTO apk_repack_seed_app_label ("
                "SeedID, AppLabel, AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW) "
                "VALUES (%s, %s, %s, %s, %s)")
        logger.info("label is exist: %s" % str(is_exist))
        logger.debug(sql_line)
        if not is_exist:
            cursor.execute(sql_line, (SeedID, AppLabel, AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW))
            conn.commit()
    except Exception, e:
        logger.error(e)


def gen_sql(candidate_list, icon_hash, seed_sha1):
    l = []
    for item in candidate_list:
        (byte_sha1, candidate_hash, is_original, repack_from, seed_label, publickey_sha1list, label_rate) = item
        if byte_sha1:
            icon_rate = compare_icon_hash(icon_hash, candidate_hash)
            rate = label_rate * 6 / 10 + icon_rate * 4 / 10
            l.append([byte_sha1, candidate_hash, is_original, repack_from, seed_label, publickey_sha1list, label_rate,
                      icon_rate, rate])
    sorted_list = sorted(l, key=operator.itemgetter(8), reverse=True)
    if sorted_list:
        c_item = sorted_list[0]
        byte_sha1 = c_item[0]
        label_rate = c_item[6]
        icon_rate = c_item[7]
        rate = c_item[8]
        sql_item = ("update ApkRepackINFO "
                    "set IsOriginal = -1, RepackFrom = 0x%s, LabelScore = %s, IconScore = %s, DefaultScore = %s "
                    "where sha1 = 0x%s;" % (seed_sha1, label_rate, icon_rate, rate, GetSha1ByBytes(byte_sha1)))
        return sql_item
    return None


def main(act, source):
    now = datetime.datetime.now()
    str_now = now.strftime("%Y%m%d%H%M%S")
    conn_cloud = connect(CLOUD_DB_USER, CLOUD_DB_PASSWD, CLOUD_DB_HOST, CLOUD_DB_NAME)
    conn_global = connect(GLOBAL_DB_USER, GLOBAL_DB_PASSWD, GLOBAL_DB_HOST, GLOBAL_DB_NAME)
    cursor_cloud = conn_cloud.cursor()
    cursor_global = conn_global.cursor()
    implFolder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "APKS")
    file_list = sorted([os.path.join(implFolder, fo) for fo in os.listdir(implFolder)])
    if act == 'add':
        logger.info("begin run: %s" % str(__file__))
        f1 = open('_insert_sql_lines.sql', 'w')
        f1.writelines('mysql -umars -h 10.64.202.11 -p --default-character-set=utf8 -e"use mars2_1; ') #TODO 根据ip和表改变
        # candidate_tuple = query_repack_info(conn)
        sql_items = ""
        for file_path in file_list:
            if os.path.isfile(file_path):
                sha1 = cal_sha1(file_path, logger)
                logger.debug(sha1)
                publickey = query_public_key(conn_cloud, sha1)
                app_label = get_app_label(conn_cloud, sha1)
                logger.debug(app_label)
                if publickey and app_label:
                    icon_hash = cal_icon_hash(file_path, logger)
                    # if source == 'GooglePlay':
                    pkg_name = query_pkg_name(conn_cloud, sha1)
                    (AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW) = query_applabel(conn_global, sha1)  
                    # original_url = "https://play.google.com/store/apps/details?id=" + pkg_name
                    insert_seed(conn_cloud, publickey, pkg_name, 1, 6, 4, 0, 95, source, str_now)
                    SeedID = check_seed_id(conn_cloud, publickey, pkg_name)
                    insert_icon(conn_cloud, SeedID, icon_hash)
                    insert_label(conn_cloud, SeedID, app_label, AppLabel_ja, AppLabel_zhCN, AppLabel_zhTW)
                    logger.info('Sha1: %s' % sha1)
                    logger.info('AppLabel: %s' % app_label)
                    logger.info('Generating Insert SQL Line:')
                    #f1.writelines(sql_line)
                    # candidate_list = get_label_rate(candidate_tuple, app_label, publickey)
                    # gen_sha1_list(candidate_list)
                    sql_item = ''
                    # sql_item = gen_sql(candidate_list, icon_hash, sha1)
                    if sql_item:
                        logger.info('Generating Update SQL Line:')
                        logger.info(sql_item)
                        sql_items += sql_item + '\n'
        f1.writelines('"')
        f1.close()
        f2 = open('_update_sql_lines.sql', 'w')
        f2.writelines(sql_items)
        f2.close()
        move_apks(act, sourcing, str_now)

    elif act == 'del':
        logger.info("begin run: %s" % str(__file__))
        for file_path in file_list:
            if os.path.isfile(file_path):
                sha1 = cal_sha1(file_path, logger)
                logger.debug(sha1)
                publickey = query_public_key(conn_cloud, sha1)
                pkg_name = query_pkg_name(conn_cloud, sha1)
                SeedID = check_seed_id(conn_cloud, publickey, pkg_name)
                if publickey and pkg_name and SeedID:
                    cursor_cloud.execute("DELETE FROM apk_repack_seed WHERE publicKeySha1 = 0x%s AND packageName = '%s'" % (publickey, pkg_name))
                    cursor_cloud.execute("DELETE FROM apk_repack_seed_icon_hash WHERE SeedID = %s", (SeedID,))
                    cursor_cloud.execute("DELETE FROM apk_repack_seed_app_label WHERE SeedID = %s", (SeedID,))
                    cursor_global.execute("UPDATE apk_repack_info "  
                                   "SET IsOriginal = 0, "
                                   "RepackFrom = NULL, "
                                   "LabelScore = NULL, "
                                   "IconScore = NULL, "
                                   "DefaultScore = NULL WHERE RepackFrom = %s", (SeedID,))

                    conn_cloud.commit()
                    conn_global.commit()
        move_apks(act, '', str_now)

    else:
        print "Add seeds in APKS/:\n    python %s add [Source Name]" % (sys.argv[0])
        print "Del seeds in APKS/:\n    python %s del" % (sys.argv[0])

    conn_cloud.close()
    conn_global.close()
    move_apks(act, sourcing, str_now)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Add seeds in APKS/:\n    python %s add [Source Name]" % (sys.argv[0])
        print "Del seeds in APKS/:\n    python %s del [Reason]" % (sys.argv[0])
        sys.exit(0)
    action = sys.argv[1]
    if action == 'add':
        sourcing = sys.argv[2]
    else:
        sourcing = ''
    main(action, sourcing)
