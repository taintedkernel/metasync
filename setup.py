from setuptools import setup, find_packages

setup(
    name='metasync',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'sqlalchemy',
        'Click',
        'python-dateutil',
        'nose',
        'paramiko',
        'sqlalchemy_jsonfield',
        'pyftpdlib',
        'dateparser',
        'colorlog'
    ],
    entry_points='''
        [console_scripts]
        ms_verify=metasync.cli:ep_verify
        ms_show_history=metasync.cli:ep_show_history
        ms_add_path=metasync.cli:ep_add_path
        ms_add_mirror=metasync.cli:ep_add_mirror
        ms_walk_scan_mirror=metasync.cli:ep_walk_scan_mirror
    ''',
)
