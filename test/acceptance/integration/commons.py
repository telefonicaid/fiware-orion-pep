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
from iotqautils.idm_keystone import IdmUtils
from tools.deploy_pep import start_docker_pep
from tools.general_utils import set_config_cb, set_config_keypass, set_config_perseo, set_config_bypass, \
    set_config_cache_projects, set_config_cache_roles, set_config_cache_gradual, start_pep, start_pep_app

__author__ = 'Jon'

from lettuce import world, step
import requests
import json
import time


@step('a url with "([^"]*)"')
def a_url_with_url(step, url):
    world.url = url


@step('a project in the user')
def a_project_in_the_user(step):
    found = False
    for domain in world.ks['environment_general']['domains']:
        if domain['name'] == world.ks['domain_ok']:
            for user in domain['users']:
                if user['name'] == world.ks['user_all']:
                    if world.ks['project_ok'] in [project['name'] for project in user['projects']]:
                        found = True
                        world.project = world.ks['project_ok']
                        break
    assert found


@step("a user in the domain")
def a_user_in_the_domain(step):
    found = False
    for domain in world.ks['environment_general']['domains']:
        if domain['name'] == world.ks['domain_ok']:
            if world.ks['user_all'] in [user['name'] for user in domain['users']]:
                found = True
                world.user = world.ks['user_all']
                break
    assert found


@step('a domain in KEYSTONE')
def a_domain_in_keystone(step):
    found = False
    if world.ks['domain_ok'] in [x['name'] for x in world.ks['environment_general']['domains']]:
        found = True
        world.domain = world.ks['domain_ok']
    assert found


@step('a domain for project_only in KEYSTONE')
def a_domain_for_project_only_in_keystone(step):
    found = False
    if world.ks['domain_project_only'] in [x['name'] for x in world.ks['environment_project']['domains']]:
        found = True
        world.domain = world.ks['domain_project_only']
    assert found


@step('a without role in domain and with "([^"]*)" user in project')
def a_without_role_user(step, user):
    found = False
    for domain in world.ks['environment_project']['domains']:
        if domain['name'] == world.ks['domain_project_only']:
            if world.ks[user] in [user_['name'] for user_ in domain['users']]:
                found = True
                world.user = world.ks[user]
                break
    assert found


@step('a "([^"]*)" role in the user project')
def a_role_in_the_user_project(step, role):
    found = False
    for domain in world.ks['environment_project']['domains']:
        if domain['name'] == world.domain:
            for user in domain['users']:
                if user['name'] == world.user:
                    if user['projects'][0]['roles'][0]['name'] == world.ac[role]:
                        found = True
                        world.project = user['projects'][0]['name']
                        break
    assert found


@step('a domain without projects in KEYSTONE')
def a_domain_without_projects_in_keystone(step):
    found = False
    if world.ks['domain_domain_only'] in [x['name'] for x in world.ks['environment_domain']['domains']]:
        found = True
        world.domain = world.ks['domain_domain_only']
    assert found, "The domain is not in the keystone structure"


@step('a "([^"]*)" user in domain without projects')
def a_group1_user_in_domain_without_projects(step, user):
    found = False
    for domain in world.ks['environment_domain']['domains']:
        if domain['name'] == world.ks['domain_domain_only']:
            if world.ks['user_create_domain'] in [user_['name'] for user_ in domain['users']]:
                found = True
                world.user = world.ks[user]
                break
    assert found


@step('a "([^"]*)" role in the user and domain')
def a_role_in_the_user_and_domain(step, role):
    found = False
    for domain in world.ks['environment_domain']['domains']:
        if domain['name'] == world.domain:
            for user in domain['users']:
                if user['name'] == world.user:
                    if user['roles'][0]['name'] == world.ac[role]:
                        found = True
                        world.project = '/'
                        break
    assert found


@step('the petition gets to the mock')
def the_petition_gets_to_contextbroker_mock(step):
    resp = requests.get(
        'http://{mock_ip}:{mock_port}/last_value'.format(mock_ip=world.mock['ip'], mock_port=world.mock['port']))
    print resp.text
    try:
        print "Entro en try"
        sent = eval(world.data)
        print "despues del sent"
        response = eval(json.loads(resp.text)['resp'])
    except Exception as e:
        print "Entro en except: %s" % e
        sent = world.data
        response = json.loads(resp.text)['resp']
    assert sent == response, 'The payload sent is "%s (%s)" and the payload proxied is "%s (%s)"' % (
    sent, type(sent), response, type(response))
    assert resp.status_code == 200, 'The response code is not 200, is: %s' % resp.status_code


@step("the Context Broker configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    if world.config_set != 'cb':
        world.config_set = 'cb'
        set_config_cb()
        start_pep_app()
        time.sleep(5)


@step("the cache gradual configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """

    world.config_set = 'cache_gradual'
    set_config_cache_gradual()
    start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                     world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
    time.sleep(5)


@step("the cache projects configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    world.config_set = 'cache_projects'
    set_config_cache_projects()
    start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                     world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
    time.sleep(5)


@step("the cache roles configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    world.config_set = 'cache_roles'
    set_config_cache_roles()
    start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                     world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
    time.sleep(5)


@step("the Keypass configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    if world.config_set != 'ks':
        world.config_set = 'ks'
        set_config_keypass()
        start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                         world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
        time.sleep(5)


@step("the Perseo configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    if world.config_set != 'cep':
        world.config_set = 'cep'
        set_config_perseo()
        start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                         world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
        time.sleep(5)


@step("the Bypass configuration")
def step_impl(step):
    """
    :type step lettuce.core.Step
    """
    if world.config_set != 'bypass':
        world.config_set = 'bypass'
        set_config_bypass()
        start_docker_pep(world.docker_ip, world.docker_user, world.docker_password,
                         world.docker_pep_user, world.docker_pep_password, world.docker_pep_container)
        time.sleep(5)


@step('the keystone proxy history reset')
def the_keystone_proxy_history_reset(step):
    requests.request('get', 'http://{ks_proxy_ip}:{ks_proxy_port}/reset_history'.format(ks_proxy_ip=world.ks_proxy_ip,
                                                                                        ks_proxy_port=world.ks_proxy_port))

@step('the petition action "([^"]*)" is asked without data')
def the_petition_is_asked(step, action):
    world.response = requests.request(action.lower(), 'http://{pep_ip}:{pep_port}/'.format(pep_ip=world.pep_host_ip, pep_port=world.pep_port) + world.url, headers=world.headers, data={})


@step('the Keystone proxy receive the last petition "([^"]*)" from PEP')
def the_keystone_proxy_doesnt_receive_any_petition(step, last_petition):
    resp = requests.request('GET', 'http://{ks_proxy_ip}:{ks_proxy_port}/last_path'.format(ks_proxy_ip=world.ks_proxy_ip, ks_proxy_port=world.ks_proxy_port)).text
    print 'last_petition: {last_petition}'.format(last_petition=last_petition)
    print 'last_petition_received: {last_petition}'.format(last_petition=resp)
    assert resp == last_petition



@step('the PEP returns an error')
def the_pep_returns_an_error(step):
    assert str(world.response.status_code) == '403'


@step('headers with format "([^"]*)"$')
def with_format_group1(step, format):
    token = IdmUtils.get_token(world.ks['user_all'], world.ks['user_all'], world.ks['domain_ok'], world.ks['platform']['address']['ip'])
    world.format = format
    headers = {
        "Accept": "application/%s" % world.format,
        'content-type': 'application/%s' % world.format,
        'Fiware-Servicepath': '/',
        'Fiware-Service': world.ks['domain_ok'],
        'X-Auth-Token': token
    }
    world.headers = headers