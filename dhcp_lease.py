from time import time
from json import dumps

class Lease(object):
    def __init__(self, **keyword_args):
        if not 'mac' in keyword_args.keys():
            self.mac = None
        else:
            self.mac = keyword_args['mac']

        if not 'ip' in keyword_args.keys():
            self.ip = None
        else:
            self.ip = keyword_args['ip']

        if not 'hostname' in keyword_args.keys():
            self.hostname = None
        else:
            self.hostname = keyword_args['hostname']

        if not 'time' in keyword_args.keys():
            self.time = 86400
        else:
            self.time = keyword_args['time']

        self.renew_times()

    def renew_times(self):
        self.create_time = int(time())
        self.lease_ends = self.create_time + self.time

    @property
    def valid(self):
        current_time = int(time())
        if self.ip == None or self.mac == None or current_time >= self.lease_ends:
            return False
        return True

    def __str__(self):
        return dumps(self.__dict__, indent=4)
