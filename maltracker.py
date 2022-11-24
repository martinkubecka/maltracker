import os
import sys
import json
import yaml
import time
import logging
import argparse
import requests
import pprint


def banner():
    print(r"""
      • ▌ ▄ ·.  ▄▄▄· ▄▄▌ ▄▄▄▄▄▄▄▄   ▄▄▄·  ▄▄· ▄ •▄ ▄▄▄ .▄▄▄  
      ·██ ▐███▪▐█ ▀█ ██• •██  ▀▄ █·▐█ ▀█ ▐█ ▌▪█▌▄▌▪▀▄.▀·▀▄ █·
      ▐█ ▌▐▌▐█·▄█▀▀█ ██▪  ▐█.▪▐▀▀▄ ▄█▀▀█ ██ ▄▄▐▀▀▄·▐▀▀▪▄▐▀▀▄ 
      ██ ██▌▐█▌▐█ ▪▐▌▐█▌▐▌▐█▌·▐█•█▌▐█ ▪▐▌▐███▌▐█.█▌▐█▄▄▌▐█•█▌
      ▀▀  █▪▀▀▀ ▀  ▀ .▀▀▀ ▀▀▀ .▀  ▀ ▀  ▀ ·▀▀▀ ·▀  ▀ ▀▀▀ .▀  ▀
    """)


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist.")
        logging.error(f"Provided file '{filename}' does not exist")
        print("\nExiting program ...\n")
        sys.exit(1)
    else:
        if filetype == "yml":
            if not filename.endswith(".yml") or filename.endswith(".yaml"):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file.")
                logging.error(f"Provided file '{filename}' is not a yaml file")
                print("\nExiting program ...\n")
                sys.exit(1)
    return True


def arg_formatter():
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(),
                                     description='Track malicious IP addresses based on the predefined country code with Feodo Tracker.')

    parser.add_argument(
        '-q', '--quiet', help="do not print banner", action='store_true')
    parser.add_argument('-c', '--config', metavar='FILE', default="config/config.yml",
                        help='config file (default: "config/config.yml")')

    # return parser.parse_args(args=None if sys.argv[1:] else ['--help'])
    return parser.parse_args()


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/{(os.path.splitext(__file__)[0]).split('/')[-1]}.log", level=logging.DEBUG)
    logger = logging.getLogger('__name__')


def json_to_file(service_name, json_object):
    report_output_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs/{service_name}.json"
    print(
        f"[{time.strftime('%H:%M:%S')}] [INFO] Writing data to '{report_output_path}'")
    logging.info(f"Writing data to '{report_output_path}'")
    with open(report_output_path, "w") as output:
        output.write(json_object)


def load_config(filename):
    with open(filename, "r") as ymlfile:
        data = yaml.safe_load(ymlfile)

    config = dict(
        feodotracker_ip_blocklist=data['feodotracker_ip_blocklist'],
        feodotracker_c2=data['feodotracker_c2'],
        country=data['country'])

    return config


def get_iocs(config_filename, config):
    iocs_dir = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/iocs"
    if not os.path.isdir(iocs_dir):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Creating directory '{iocs_dir}' for storing IOCs")
        logging.info(f"Creating directory '{iocs_dir}' for storing IOCs'")
        os.mkdir(iocs_dir)

    # list is generated every 5 minutes
    feodotracker_ip_blocklist_url = config['feodotracker_ip_blocklist']
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching Feodo Tracker's Botnet C2 IP Blocklist ...")
    logging.info(f"Fetching Feodo Tracker's Botnet C2 IP Blocklist'")
    response = requests.get(feodotracker_ip_blocklist_url)
    feodotracker_ip_blocklist = json.loads(response.content.decode("utf-8"))
    json_object = json.dumps(feodotracker_ip_blocklist, indent=4)
    json_to_file("feodotracker_ip_blocklist", json_object)

    # IP addresses that were acting as a botnet C2 within the past 30 days
    feodotracker_c2_url = config['feodotracker_c2']
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Fetching latest Feodo Tracker's Botnet C2 Indicators Of Compromise ...")
    logging.info(
        f"Fetching latest Feodo Tracker's Botnet C2 Indicators Of Compromise'")
    response = requests.get(feodotracker_c2_url)
    feodotracker_c2 = json.loads(response.content.decode("utf-8"))
    json_object = json.dumps(feodotracker_c2, indent=4)
    json_to_file("feodotracker_c2", json_object)

    with open(config_filename, 'w') as file:
        yaml.dump(config, file)

    return feodotracker_ip_blocklist, feodotracker_c2


def search(feodotracker_ip_blocklist, feodotracker_c2, country):
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Searching for country code '{country}' in IOCs ...")
    logging.info(f"Searching for country code '{country}' in IOCs ...")
    status = False

    # list is generated every 5 minutes
    for entry in feodotracker_ip_blocklist:
        if entry['country'] == country:
            pprint.pprint(f"{entry}")
            status = True

    # IP addresses that were acting as a botnet C2 within the past 30 days
    for entry in feodotracker_c2:
        if entry['country'] == country:
            pprint.pprint(entry)
            status = True

    if not status:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] No matches were found")
        logging.info(f"No matches were found")


def main():
    init_logger()
    args = parse_arguments()
    if not args.quiet:
        banner()

    config_path = args.config
    if is_valid_file(config_path, "yml"):
        print(
            f"[{time.strftime('%H:%M:%S')}] [INFO] Loading config '{config_path}' ...")
        logging.info(f"Loading config '{config_path}'")
        config = load_config(config_path)

    feodotracker_ip_blocklist, feodotracker_c2 = get_iocs(config_path, config)
    search(feodotracker_ip_blocklist, feodotracker_c2, config['country'])


if __name__ == '__main__':
    main()
