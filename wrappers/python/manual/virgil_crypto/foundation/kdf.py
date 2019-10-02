from abc import ABCMeta, abstractmethod


class Kdf(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def derive(self, data, key_len, key):
        raise NotImplementedError()
