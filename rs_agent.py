'''
Created on 21/03/2020

@author: lee
'''
import sys
import os
from configparser import ConfigParser

from twisted.logger import Logger, eventAsText, FileLogObserver
from twisted.internet import endpoints, ssl, defer, task, protocol
from twisted.web import client
from twisted.spread import pb
import treq


CONFIG_DEFAULTS = {'server': {'server_name': 'nzrs.begg.digital',
                                 'server_https': '8080',
                                 'server_port': '6923',
                                 'allow_management': 'False'},
                    'auto_rx': {'address': 'http://localhost:5000',
                                'path':'/home/pi/radiosonde_auto_rx',
                                'telemetry_port': '55673'}}
CONFIG_FILE_LIST = ['/etc/rs_agent.conf', '~/.rs_agent.conf',
                    '~/.config/rs_agent/config.conf', 'config.conf']


log = Logger()
log.observer.addObserver(FileLogObserver(sys.stdout, lambda e: eventAsText(e) + "\n"))

class HorusRepeater(protocol.DatagramProtocol):
    def __init__(self, server_iface):
        self.iface = server_iface
    
    def datagramReceived(self, datagram, address):
        self.iface.callRemote('upload_telemetry', datagram)
        
def any_active_sdr(jdict):
    '''Are any of the sdrs not scanning or idle'''
    allowed = ['Scanning', 'Not Tasked']
    return all(state not in allowed for _, state in jdict.items())

def print_and_continue(content):
    print(content)
    return content

class RunCommand(protocol.ProcessProtocol):
    def __init__(self):
        self._out = []
        self._err = []
        self.defered = defer.Deferred()
    
    def connectionMade(self):
        protocol.ProcessProtocol.connectionMade(self)
        self.transport.closeStdin()
        
    def outReceived(self, data):
        self._out.append(data)
        
    def errReceived(self, data):
        self._err.append(data)
    
    def processEnded(self, reason):
        if reason.value.exitCode == 0:
            self.defered.callback((reason.value.exitCode, b''.join(self._out), b''.join(self._err)))
        else:
            self.defered.errback((reason.value.exitCode, b''.join(self._out), b''.join(self._err)))

class ManagementInterface(pb.Referenceable):
    '''Interface provided to server to have it manage this device'''
    
    def __init__(self, config, reactor):
        self.config = config
        self.reactor = reactor
    
    def remote_ping(self):
        '''Return pong, test connection is alive'''
        log.info('Received ping remote request')
        return 'Pong'
    
    def remote_get_name(self):
        '''Returns the station's name'''
        log.info('Received get_name remote request')
        d = treq.get('%s/get_config' % self.config['auto_rx']['address'])
        d.addCallback(treq.json_content).addCallback(lambda jdict: jdict['habitat_uploader_callsign'])
        return d
    
    def remote_get_auto_rx_version(self):
        '''Return the version of radionsonde_auto_rx'''
        log.info('Received get_auto_rx_version remote request')
        return treq.get('%s/get_version' % self.config['auto_rx']['address']).addCallback(treq.text_content)
    
    def remote_is_tracking(self):
        '''Return true if auto rx is tracking a radiosonde'''
        log.info('Received is_tracking remote request')
        d = treq.get('%s/get_task_list' % self.config['auto_rx']['address'])
        d.addCallback(treq.json_content).addCallback(any_active_sdr)
        # if any of response dict value is not "Scanning"
        return d
    
    
    @defer.inlineCallbacks
    def remote_update_rs_agent(self):
        '''Update this software'''
        log.info('Received update_rs_agent remote request')
        
        result_set = []
        cmd_proto = RunCommand()
        self.reactor.spawnProcess(cmd_proto, 'git', ['git', 'pull'])
        res_git = yield cmd_proto.defered
        result_set.append(res_git)
        
        if res_git[1] != b'Already up to date.\n':
        
            #This should kill this process and it won't have time to return the result unless it fails
            cmd_proto = RunCommand()
            self.reactor.spawnProcess(cmd_proto, 'sudo', ['sudo', 'service', 'rs_agent', 'restart'])
            res_restart = yield cmd_proto.defered
            result_set.append(res_restart)
        
        return result_set
    
    @defer.inlineCallbacks
    def remote_update_auto_rx(self):
        '''Update the Radiosonde Auto RX software'''
        log.info('Received update_auto_rx remote request')
        result_set = []
        cmd_proto = RunCommand()
        self.reactor.spawnProcess(cmd_proto, 'git', ['git', 'pull'], path=self.config['auto_rx']['path'])
        res_git = yield cmd_proto.defered
        result_set.append(res_git)
        
        if res_git[1] != b'Already up to date.\n':
            
        
            cmd_proto = RunCommand()
            self.reactor.spawnProcess(cmd_proto, 'bash', ['./build.sh'],
                                      path=os.path.join(self.config['auto_rx']['path'], 'auto_rx'))
            res_build = yield cmd_proto.defered
            result_set.append(res_build)
            
            #rewrite station.cfg?
            
            if self.config['auto_rx'].getboolean('restart', fallback=True):
                cmd_proto = RunCommand()
                self.reactor.spawnProcess(cmd_proto, 'sudo', ['sudo', 'service', 'auto_rx', 'restart'])
                res_restart = yield cmd_proto.defered
                result_set.append(res_restart)
        
        return result_set
    

def start_relaying_horus_telemetry(server_iface, reactor, config):
    telem_proto = HorusRepeater(server_iface)
    reactor.listenUDP(int(config['auto_rx']['telemetry_port']), protocol=telem_proto)


@defer.inlineCallbacks
def setup(reactor, config):
    #not yet complete
    agent = client.Agent(reactor)
    
    page = yield agent.request(b'POST', ('http://%s:%s/cert-signing' % (config['server']['server_name'], config['server']['server_https'])).encode('utf-8'))
    
    yield page

@defer.inlineCallbacks
def initial_connection(reactor, config):
    #factory = protocol.Factory.forProtocol(EdgeProtocol)
    factory = pb.PBClientFactory()
    with open('server.pem') as cfile:
        certData = cfile.read()
    with open('ca.crt') as cfile:
        authData = cfile.read()
    clientCertificate = ssl.PrivateCertificate.loadPEM(certData)
    authority = ssl.Certificate.loadPEM(authData)
    options = ssl.optionsForClientTLS(config['server']['server_name'], authority,
                                      clientCertificate)
    endpoint = endpoints.SSL4ClientEndpoint(reactor, config['server']['server_name'], int(config['server']['server_port']),
                                            options)
    edgeClient = yield endpoint.connect(factory)
    
    server_iface = yield factory.getRootObject()
    start_relaying_horus_telemetry(server_iface, reactor, config)
    
    if config['server'].getboolean('allow_management', fallback=False):
        server_iface.callRemote('register_management_interface', ManagementInterface(config, reactor))
        log.info('Registered management interface')
    else:
        log.info('Not providing management interface')
        
    def keepalive_task():
        server_iface.callRemote('ping').addTimeout(5, reactor).addErrback(lambda _err: edgeClient.transport.loseConnection())
    
    l = task.LoopingCall(keepalive_task)
    l.start(3*60.0) # ping the server every 3 minutes

    done = defer.Deferred()
    edgeClient.connectionLost = lambda reason: done.callback(None)
    yield done

@defer.inlineCallbacks
def main(reactor):
    
    config = ConfigParser()
    config.read_dict(CONFIG_DEFAULTS)
    config.read(CONFIG_FILE_LIST)
    
    if False:
        yield setup(reactor, config)
    
    foo = yield initial_connection(reactor, config)

    yield foo
    

if __name__ == '__main__':
    task.react(main)
