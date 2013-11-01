from distutils.core import setup
from setuptools import find_packages

setup(
    name='zaapi',
    version='0.2.9',
    author='Aaron McSorley',
    author_email='a@aaronmcsorley.com',
    scripts=['bin/zaapi'],
    url='https://github.com/zenoss/zaas/tree/master/zaapi',
    license='GPLv2',
    description='Zenoss as a service API',
    long_description=open('README.rst').read(),
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=['tornado', 'argparse', 'crypto', 'magic', 'pychef'],
    data_files = [ ('/etc/init.d',['zaapi/init-script/zaapi']),
                   ('/etc/zaapi',['zaapi/config/zaapi.conf']),
                   ('/etc/pki/zaapi',['zaapi/certs/key.pem']),
                   ('/etc/pki/zaapi',['zaapi/certs/cert.pem']),
                   ('/etc/pki/zaapi',['zaapi/certs/openssl.cnf']),
    ],
)
