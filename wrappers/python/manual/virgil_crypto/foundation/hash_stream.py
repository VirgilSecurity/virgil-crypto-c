from abc import ABCMeta, abstractmethod


class HashStream(object):

    __metaclass__ = ABCMeta

    @abstractmethod
    def start(self):
        raise NotImplementedError()

    @abstractmethod
    def update(self, data):
        raise NotImplementedError()

    @abstractmethod
    def finish(self):
        raise NotImplementedError()
