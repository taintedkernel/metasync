from setuptools import setup, find_packages
import platform

packages = [
        'Click',
        'python-dateutil',
        'nose',
        'paramiko',
        'pyopenssl',
        'pyftpdlib',
        'dateparser',
        'colorlog',
        'SQLAlchemy-JSONField',
        'SQLAlchemy'
    ]


if 'CYGWIN' not in platform.system():
    packages.append('pysendfile')

setup(
    name='metasync',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=packages,
    entry_points='''
        [console_scripts]
        ms_verify=metasync.cli:ep_verify
        ms_show_history=metasync.cli:ep_show_history
        ms_add_path=metasync.cli:ep_add_path
        ms_update_path=metasync.cli:ep_update_path
        ms_add_mirror=metasync.cli:ep_add_mirror
        ms_walk_scan_mirror=metasync.cli:ep_walk_scan_mirror
    ''',
)
