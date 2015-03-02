# -*- coding: utf-8 -*-
"""
Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U

This file is part of fiware-orion-pep

fiware-orion-pep is free software: you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

fiware-orion-pep is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public
License along with fiware-orion-pep.
If not, see http://www.gnu.org/licenses/.

For those usages not covered by the GNU Affero General Public License
please contact with::[iot_support@tid.es]
"""

__author__ = 'Jon Calderin Goñi <jon.caldering@gmail.com>'

import requests
import json

from iotqautils.idm_keystone import IdmUtils
from tools.general_utils import convert

from integration.commons import *
from requests.exceptions import ConnectionError

@step('url with "([^"]*)" and the actionType attribute "([^"]*)"')
def a_url_with_group1_and_the_actiontype_attribute_group2(step, url, action_type):
    """
    Define the url and the action type sent in the payload
    :param step:
    :param url:
    :param action_type:
    :return:
    """
    world.url = url
    world.action_type = action_type


@step('a context broker "([^"]*)" petition is asked to PEP with "([^"]*)" format')
def a_context_broker_petition_is_asked_to_pep_with_format(step, action, format):
    """
    Set the header with the format and action given, and the action_type, project, domain and url set before. Then send the request to PEP
    :param step:
    :param action:
    :param format:
    :return:
    """
    token = IdmUtils.get_token(world.user, world.user, world.domain, world.ks['platform']['address']['ip'], world.ks['platform']['address']['port'])
    headers = {
        "Accept": "application/%s" % format,
        'content-type': 'application/%s' % format,
        'Fiware-Servicepath': world.project,
        'Fiware-Service': world.domain,
        'X-Auth-Token': token
    }
    world.headers = headers
    url = 'http://{pep_ip}:{pep_port}'.format(pep_ip=world.pep_host_ip, pep_port=world.pep_port) + world.url
    if hasattr(world, 'action_type') and world.action_type != '':
        if format == 'json':
            data = {
                'updateAction': world.action_type
            }
            world.data = json.dumps(data)
        else:
            data = "<updateAction>%s</updateAction>" % world.action_type
            world.data = data
    else:
        if format == 'json':
            world.data = json.dumps({})
        else:
            world.data = '<xml></xml>'
    try:
        requests.request(action.lower(), url, headers=headers, data=world.data)
    except ConnectionError as e:
        assert False, '''There was an error with the connection with the following data: \n
        \tAction: {action}\n
        \tUrl: {url}\n
        \tHeaders: {headers}\n
        \tData: {data}\n
        \t error: {error}
        '''.format(action=action.lower(), url=url, headers=headers, data=world.data, error=e)








