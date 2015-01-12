# -*- coding: utf-8 -*-
"""
(c) Copyright 2014 Telefonica, I+D. Printed in Spain (Europe). All Rights
Reserved.

The copyright to the software program(s) is property of Telefonica I+D.
The program(s) may be used and or copied only with the express written
consent of Telefonica I+D or in accordance with the terms and conditions
stipulated in the agreement/contract under which the program(s) have
been supplied.
"""

__author__ = 'Jon'

import requests
import json

from integration.commons import *
from iotqautils.idm_keystone import IdmUtils


@step('a CEP "([^"]*)" petition is asked to PEP')
def a_cep_petition_is_asked_to_pep(step, action):
    token = IdmUtils.get_token(world.user, world.user, world.domain, world.ks['platform']['address']['ip'])
    headers = {
        "Accept": "application/json",
        'content-type': 'application/json',
        'Fiware-Servicepath': world.project,
        'Fiware-Service': world.domain,
        'X-Auth-Token': token
    }
    data = {'test_payload': 'test_value'}
    world.data = json.dumps(data)
    requests.request(action.lower(), 'http://{pep_ip}:{pep_port}'.format(pep_ip=world.pep_host_ip, pep_port=world.pep_port) + world.url, headers=headers, data=json.dumps(data))




