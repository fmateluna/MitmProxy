# -*- coding: utf-8 -*-
import os, fnmatch
import json
import argparse
import re
import sqlite3
import base64

# Criteria of seek
criteria_json = {}
criteria_json['ext'] = 'jsp,xhtml,html,htm,xhtml,js,php,css'


def eval_file(file_name, eval_regex):
    eval_file = open(file_name, "r")
    regex = re.compile(eval_regex)
    lxl = 0
    result_file = []
    for line in eval_file:
        lxl += 1
        four_letter_words = regex.findall(line)
        for word in four_letter_words:
            evuation = {}
            print "\t{}".format(file_name)
            ref = line.strip()
            print "\t\t{}:{} ".format(lxl, ref[:150])
            evuation['filename'] = file_name
            evuation['line'] = lxl
            evuation['source'] = ref
            result_file.append(evuation)
    return result_file


def get_eval(jsonFile):
    with open(jsonFile) as json_file:
        json_data = json.load(json_file)
    return json_data


def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def create_db():
    conn = sqlite3.connect('report.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE report
                 (category text, description text, path text, line text, source BLOB, severity text)''')
    conn.commit()
    conn.close()


def insert_result(category, description, path, line, source, severity):
    conn = sqlite3.connect('report.db')
    sql = '''INSERT INTO report (category , description , path , line , source , severity )
    VALUES(?, ?, ?,?, ?, ?);'''
    conn.execute(sql,[category, description, path, line, source, severity])
    conn.commit()
    conn.close()


def add_to_csv(cotegory, description, path, line, source, severity):
    with open("result.csv", "a") as myfile:
        myfile.write("{};{};{};{};{};{}\n".format(cotegory, description, path, line, base64.b64encode(source), severity))


def EvalKode(config_file, eval_path):
    create_db()
    criteria_json['eval'] = get_eval(config_file)
    print "Find result in {}".format(eval_path)
    for evalKode in criteria_json['eval']:
        for ext in criteria_json['ext'].split(","):
            for filename in find_files(eval_path, '*.{}'.format(ext)):
                evalKode['result'] = []
                evalKode['result'].extend(eval_file(filename, evalKode['regex']))
                if len(evalKode['result'])>0:
                    for result in evalKode['result']:
                        insert_result(evalKode['concept'], evalKode['description'], filename, result['line'], result['source'], evalKode['severity'])
        print "\t {} : {} = {} cases".format(evalKode['concept'], evalKode['description'], len(evalKode['result']))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EvalKode")
    parser.add_argument('-k', help="Config file with concepto to evaluate", default=None)
    parser.add_argument('-e', help="Path where a find errors", default=None)
    args = parser.parse_args()
    confing_file = args.k
    eval_path = args.e
    EvalKode(confing_file, eval_path)

