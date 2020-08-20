#! /usr/bin/env python3
# Author: xtonousou
# Description: pip's setup.py for rshelly

from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='rshelly',  
    version='0.1',
    scripts=['rshelly', ],
    author='Sotirios Roussis a.k.a. xtonousou',
    author_email='sroussis@xtonousou.xyz',
    description='A reverse shell payload generator',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/xtonousou/rshelly',
    install_requires=[
        'Click',
    ],
    include_package_data=True,
    packages=find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    entry_points='''
        [console_scripts]
        rshelly=rshelly.rshelly:main
    ''',
)
