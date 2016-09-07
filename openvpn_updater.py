#!/usr/bin/env python
import boto.ec2
import argparse
import ConfigParser
import os
import re
import sys
from jinja2 import Environment, FileSystemLoader
from hashlib import md5
import logging
import subprocess
import socket


def get_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-c', action='store',
                        dest='config_file',
                        help='Configuration File',
                        required=True)

    parser.add_argument('-d', action='store_true',
                        dest='debug',
                        help='Enable debug mode')

    return parser.parse_args()


def get_aws_params(config_file):
    optional_defaults = {'addresses': '', 'instances': ''}
    config = ConfigParser.ConfigParser(defaults=optional_defaults)
    config.read(config_file)

    for optional_section in ('excluded', 'persistent'):
        if not config.has_section(optional_section):
            config.add_section(optional_section)

    aws_access_key_id = config.get('main', 'aws_access_key_id')
    aws_secret_access_key = config.get('main', 'aws_secret_access_key')
    region = config.get('main', 'region')
    target_conf_file = config.get('main', 'config_file')
    service = config.get('main', 'service')
    excluded_instances = config.get('excluded', 'instances')
    persistent_addresses = config.get('persistent', 'addresses')
    aws_params = {'aws_access_key_id': aws_access_key_id, 'aws_secret_access_key': aws_secret_access_key,
                  'region': region, 'excluded_instances': excluded_instances,
                  'persistent_addresses': persistent_addresses, 'target_conf_file': target_conf_file,
                  'service': service}

    return aws_params


def get_ec2_info(aws_params):
    ec2 = list()
    conn = boto.ec2.connect_to_region(aws_params['region'],
                                      aws_access_key_id=aws_params['aws_access_key_id'],
                                      aws_secret_access_key=aws_params['aws_secret_access_key'])

    reservations = conn.get_all_instances()
    for reservation in reservations:
        for instance in reservation.instances:
            if instance.tags.get('Name') not in re.split(', *', aws_params['excluded_instances']) and \
                            'jenkins_slave_type' not in instance.tags and \
                            instance.ip_address is not None:
                ec2.append(
                    {'name': instance.tags.get('Name'), 'ext_ipv4': instance.ip_address}
                )

    for address in re.split(', *', aws_params['persistent_addresses']):
        if is_valid_ipv4_address(address):
            ec2.append(
                {'name': 'persistent', 'ext_ipv4': address}
            )

    return ec2


def create_openvpn_config(ec2_info):
    path = os.path.dirname(os.path.abspath(__file__))
    template_environment = Environment(
        autoescape=False,
        loader=FileSystemLoader(os.path.join(path, 'templates')),
        trim_blocks=False)

    return template_environment.get_template('server.conf.j2').render(title="Openvpn config", hosts=ec2_info)


def restart_service(service):
    command = ['/sbin/service', service, 'restart']
    status = subprocess.call(command, shell=False)

    return status


def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:
        return False

    return True


def main():
    log = logging.getLogger(__name__)
    args = get_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    log.debug('Openvpn config generator started')

    aws_params = get_aws_params(args.config_file)
    ec2_info = get_ec2_info(aws_params)

    filename = aws_params['target_conf_file']
    generated_hash = md5(create_openvpn_config(ec2_info)).hexdigest()
    log.debug('md5 hash of generated config is %s' % generated_hash)

    if os.path.isfile(filename):
        log.debug('File %s exists' % filename)
        with open(filename, "rb") as f:
            file_hash = md5(f.read()).hexdigest()
            log.debug('md5 hash of %(configfile)s is %(hash)s' % {'configfile': filename, 'hash': file_hash})
    else:
        file_hash = False
        log.debug('File %s does not exist' % filename)

    if not generated_hash == file_hash:
        log.info('Changes in %s found or no config file exists' % filename)
        log.info('Configfile generation started')
        try:
            with open(filename, "wb") as fh:
                fh.write(create_openvpn_config(ec2_info))
        except:
            log.error('Config file %s generation FAILED' % filename)
            sys.exit(1)

        log.info('Config file %s generation DONE' % filename)
        restart_service(aws_params['service'])
        log.info('Openvpn restarted')
    else:
        log.info('No changes against config file %s' % filename)


if __name__ == "__main__":
    main()
