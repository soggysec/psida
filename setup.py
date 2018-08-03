#!/usr/bin/env python
# -*- encoding: utf8 -*-
#

from setuptools import setup

setup(name='psida',
      version='1.3',
      description='IDA plugin collaborate across IDBs',
      author='Soggysec / Argus Security Team',
      url='https://www.github.com/soggysec/psida',
      packages=['psida'],
      install_requires=[
          'pyzmq',
      ],
      license="BSD",
      entry_points={
          "idapython_plugins": [
              "psida=psida.idb_push_plugin:IdbPushPlugin"
          ]
      })
