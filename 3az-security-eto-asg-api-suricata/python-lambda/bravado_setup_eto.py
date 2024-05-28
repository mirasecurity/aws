import base64
import boto3
import json
import logging
import os
import ssl
import time
import traceback
import urllib3

from botocore.exceptions import ClientError
from bravado.requests_client import RequestsClient
from bravado.client import SwaggerClient, SwaggerFormat
from bravado.exception import HTTPBadRequest, HTTPInternalServerError, BravadoConnectionError
from datetime import datetime


region = os.environ['Region']
ec2 = boto3.client('ec2', region_name=region)
SM = boto3.client('secretsmanager', region_name=region)

timeout = urllib3.Timeout(connect=2.0, read=2.0)
http = urllib3.PoolManager(assert_hostname=False,
                           cert_reqs='CERT_NONE', timeout=timeout)
logging.getLogger("urllib3").setLevel(logging.ERROR)


def connect(server_url, username=None, password=None, ssl_verify=True, new_password=None):
    if not ssl_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http_client = RequestsClient(ssl_verify=ssl_verify)
    swagger_client = SwaggerClient.from_url(
        '%s/swagger.json' % server_url,
        http_client=http_client,
        config={
            'validate_responses': False,
            'validate_requests': True,
            'validate_swagger_spec': False,
            'use_models': False,
            'formats': [
                SwaggerFormat(
                    format='uri',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='email',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='ipv4',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
                SwaggerFormat(
                    format='ipv6',
                    to_wire=lambda b: b if isinstance(b, str) else str(b),
                    to_python=lambda s: s if isinstance(s, str) else str(s),
                    validate=lambda v: v,
                    description='Converts [wire]string:byte <=> python byte',
                ),
            ],
        },
    )
    if new_password is not None and username is not None and password is not None:
            # Change Default Password
            login = swagger_client.auth.auth_login_create(
                data=swagger_client.get_model('Login')(
                    username=username, password=password, new_password=new_password)
            ).response().result
    elif username is not None and password is not None:
        login = swagger_client.auth.auth_login_create(
            data=swagger_client.get_model('Login')(
                username=username, password=password)
        ).response().result
    swagger_client.server_url = server_url
    return swagger_client


def poll_task(client, id, task_desc):
    while True:
        time.sleep(10)
        task_status = client.tasks.tasks_read(id=id).response().result
        if task_status['status'] == 'error':
            raise Exception('%s failed: %s' %
                            (task_desc, task_status['error']))
        elif task_status['status'] == 'completed':
            print('%s completed: %s' % (task_desc, task_status['result']))
            return task_status
        else:
            print('%s progress: %s%%' %
                  (task_desc, task_status['progress']*100))


def get_aws_secret(SMID):
    if SMID == "":
        return None

    try:
        secret_ca = SM.get_secret_value(SecretId=SMID)
        return (secret_ca['SecretString'])
    except ClientError as e:
        print(e)
        return None


def split_cert(pem_contents):
    pem_contents.strip()

    # Find start and end of certificate block
    cert_start = pem_contents.find('-----BEGIN CERTIFICATE-----')
    cert_end = pem_contents.find(
        '-----END CERTIFICATE-----') + len('-----END CERTIFICATE-----')

    # Find start and end of private key block
    if pem_contents.find('-----BEGIN RSA PRIVATE KEY-----') != -1:
        key_start = pem_contents.find('-----BEGIN RSA PRIVATE KEY-----')
        key_end = pem_contents.find(
            '-----END RSA PRIVATE KEY-----') + len('-----END RSA PRIVATE KEY-----')
    elif pem_contents.find('-----BEGIN PRIVATE KEY-----') != -1:
        key_start = pem_contents.find('-----BEGIN PRIVATE KEY-----')
        key_end = pem_contents.find(
            '-----END PRIVATE KEY-----') + len('-----END PRIVATE KEY-----')

    # Save the PKI data to different variables
    if all(pki_index != -1 for pki_index in [cert_start, cert_end, key_start, key_end]):
        cert_data = pem_contents[cert_start:cert_end]
        key_data = pem_contents[key_start:key_end]
    else:
        raise Exception('pemfile could not be read')
    return cert_data, key_data


def add_full_policy(client, uid):
    # Check if user has specified a CA to reuse and is available
    pem_contents = get_aws_secret(os.environ['CASecretsId'])
    if pem_contents:
        cert_data, key_data = split_cert(pem_contents)
        new_pki = client.pki.pki_create(
            data=client.get_model('PKI')(
                pki_type='internal-ca',
                data_entries=[{
                    'data_type': 'x509.crt',
                    'encoding': 'pem',
                    'value': cert_data,
                }, {
                    'data_type': 'key',
                    'encoding': 'pem',
                    'value': key_data,
                }],
            )
        ).response().result
    else:
        # create a new CA on ETO
        new_pki = client.pki.pki_create(
            data=client.get_model('PKI')(
                pki_type='internal-ca',
                data_entries=[],
                csr_data={
                    'common_name': 'test',
                    'self_signed': True,
                },
            )
        ).response().result

    # create PKI matchlist
    new_pki_matchlist = client.pkilists.pkilists_create(
        data=client.get_model('PKIList')(
            name='PKI matchlist: %s' % uid,
            pki_type='endpoint',
            entries=[],
        )
    ).response().result

    # Check if any server certs exist in Secrets Mgr and add to ETO PKI list
    if os.environ['CertsSecretsTag']:
        certs_found = SM.list_secrets(IncludePlannedDeletion=True,
            MaxResults=100, Filters=[
                {
                    'Key': 'tag-key',
                    'Values': [os.environ['CertsSecretsTag'],]
                },
            ],
            SortOrder='asc'
        )

        for cert in certs_found['SecretList']:
            try:
                pem_contents = get_aws_secret(cert['Name'])
                if pem_contents:
                    cert_data, key_data = split_cert(pem_contents)
                    new_pki_crt = client.pki.pki_create(
                        data=client.get_model('PKI')(
                            pki_type='endpoint',
                            pki_lists=[new_pki_matchlist['url']],
                            data_entries=[{
                                'data_type': 'x509.crt',
                                'encoding': 'pem',
                                'value': cert_data,
                            }, {
                                'data_type': 'key',
                                'encoding': 'pem',
                                'value': key_data,
                            }],
                        )
                    ).response().result
            except HTTPBadRequest as err:
                print('Validation Error: %s' % str(err.response.text))
            except Exception as e:
                print(e)

    # create sni matchlist and entry
    new_matchlist = client.matchlists.matchlists_create(
        data=client.get_model('MatchList')(
            name='sni matchlist: %s' % uid,
            list_type='domain',
        )
    ).response().result

    # Bypass ssm.region.amazonaws.com so endpoints EC2 nitro cards can access AWS APIs
    new_matchpattern = client.matchpatterns.matchpatterns_create(
        data=client.get_model('MatchPattern')(
            value='ssm[.].*[.]amazonaws[.]com',
            pattern_type='regex',
            match_list=new_matchlist['url'],
        )
    ).response().result

    # create policy, allow SNI not matching Cert DomainName for testbed
    new_policy = client.policies.policies_create(
        data=client.get_model('Policy')(
            name='policy: %s' % uid,
            catch_all_action='universal-decrypt',
            catch_all_error_action='cut',
            catch_all_pki=new_pki['url'],
            universal_decrypt_int_ca=new_pki['url'],
            universal_decrypt_endpoint_list=new_pki_matchlist['url'],
            x509_status_actions_decrypt_hostname_mismatch='allow',
        )
    ).response().result

    # create rule list
    new_rulelist = client.rulelists.rulelists_create(
        data=client.get_model('RuleList')(
            name='rulelist: %s' % uid,
            rules=[],
            policies=[],
        )
    ).response().result

    # link policy and rulelist
    new_policy_rulelist = client.policyrulelists.policyrulelists_create(
        data=client.get_model('PolicyRuleList')(
            policy=new_policy['url'],
            rule_list=new_rulelist['url'],
        )
    ).response().result

    # add a policy rule
    new_rule = client.rules.rules_create(
        data=client.get_model('Rule')(
            action='cut',
            error_action='reject',
            sni_list=new_matchlist['url'],
            rule_list=new_rulelist['url'],
            cert_categories=[],
            sni_categories=[],
            category_match_mode='auto',
            server_categories=[],
        )
    ).response().result
    return new_policy['url']


def add_and_activate_segment(client, uid, policy, tool_ip):
    # get nic info
    hw_info = client.segments.segments_hardware_discovery().response().result
    if not hw_info['cards']:
        raise Exception('no cards found on system.')
    first_card = hw_info['cards'][0]
    # create segment
    new_segment = client.segments.segments_create(
        data=client.get_model('Segment')(
            name='segment: %s' % uid,
            policy=policy,
            mode='net-inline/app-passive/port-per-dir',
            ports=[],
            plaintext_marks=[],
            vlan_mappings=[],
            first_port=first_card['ports'][0]['port_id'],
            hw_model=first_card['model'],
            logical_slot='100',
            generated_max_packet_size=0,
            prevent_mirroring_mac='00:00:00:00:00:00',
            vlan_map_src_mac_tls='00:15:4D:5D:DE:C0',
            vlan_map_src_mac_tls_default_enabled=True,
            vlan_map_src_mac_ssh='00:15:4D:5D:DE:00',
            vlan_map_src_mac_ssh_default_enabled=True,
            gwlb_enabled=True,
            gwlb_plaintext_port_tunnel_type='vxlan',
            gwlb_plaintext_port_tunnel_options='{"remote_ip": "%s", "key": 1}' % tool_ip,
        )
    ).response().result
    # activate segment and poll the task until finished
    activate_task = client.segments.segments_activate(
        data=client.get_model('SegmentActivate')(
            activate_segments=[new_segment['id']],
            deactivate_segments=[],
            confirm=True,
        )
    ).response().result
    poll_task(client, activate_task['task_id'], 'activation')
    return new_segment['id']


def add_policy_and_activate_segment(server_url, username, password, tool_ip, ssl_verify=True, new_password=None):
    client = connect(server_url, username, password, ssl_verify, new_password)
    uid = datetime.now()
    policy_url = add_full_policy(client, uid)
    add_and_activate_segment(client, uid, policy_url, tool_ip)


def lambda_handler(event, context):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    secrets = SM.get_secret_value(SecretId=os.environ['SecretsId'])
    secrets_json = json.loads(secrets['SecretString'])
    eto_username = "admin"
    eto_password = secrets_json['Decryptorpassword']

    print("Received event: " + json.dumps(event))
    state = event['detail-type']
    if state == "EC2 Instance Launch Unsuccessful":
        print("Launch Unsuccessful %s" % (event['detail']['StatusMessage']))
        return
    instances = [event['detail']['EC2InstanceId']]
    if state == "EC2 Instance Terminate Successful":
        print("%s EC2 now terminated" % instances)
        return

    full = (ec2.describe_instances(InstanceIds=instances))
    private_enis = full["Reservations"][0]["Instances"][0]["NetworkInterfaces"]
    az = full["Reservations"][0]["Instances"][0]["Placement"]["AvailabilityZone"]
    tool_ips = json.loads(os.environ['NLB_IPs'])
    tool_ip = tool_ips[az]
    if len(private_enis) == 0:
        print("%s error no interfaces, EC2 may be fully terminated" % instances)
        return

    for interface in private_enis:
        if interface["Attachment"]["DeviceIndex"] == 0:
            datapath_ip = (interface["PrivateIpAddress"])
        elif interface["Attachment"]["DeviceIndex"] == 1:
            eto_mgmt_hostname = (interface["PrivateIpAddress"])
            eto_url = "https://%s/api" % eto_mgmt_hostname

    print("%s %s, Management IP:%s, Datapath IP:%s" %
          (instances, state, eto_mgmt_hostname, datapath_ip))

    if state == "EC2 Instance Launch Successful":
        eto_online = False
        print("%s Waiting for ETO API to come online..." % instances)
        for i in range(120):
            try:
                response = http.request("GET", eto_url)
                if response.status:
                    eto_online = True
                    break
            except:
                time.sleep(5)
        if not eto_online:
            print("%s Could not connect to ETO, exiting" % instances)
            return

        try:
            ssl_verify = False
            default_password = instances[0]
            add_policy_and_activate_segment(
                eto_url, eto_username, default_password, tool_ip, ssl_verify, eto_password)
            print("%s PKI, Policy and Segment Setup and Activated" % (instances))
        except HTTPBadRequest as err:
            print('Validation Error: %s' % str(err))
            print('Validation Error: %s' % str(err.response.text))
        except HTTPInternalServerError as error:
            msg = error.response.text if error.response.text else error.response.reason
            print('Server Error: %s' % msg)
        except BravadoConnectionError as err:
            print('Connection Error: %s\n%s' % (str(err), traceback.format_exc()))
        except Exception as err:
            print('Unhandled Error: %s: %s' % (type(err).__name__, str(err)))

    else:
        print("%s other state change for ec2 %s" % (instances, state))
