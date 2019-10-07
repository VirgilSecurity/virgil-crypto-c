from abc import ABCMeta, abstractmethod


class Hash(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def hash(self, data, digest):
        raise NotImplementedError()
