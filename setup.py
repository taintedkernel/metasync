from setuptools import setup, find_packages

setup(
    name='metasync',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'sqlalchemy',
        'Click',
        'click-log',
        'nose'
    ],
    entry_points='''
        [console_scripts]
        metasync=metasync:scan
    ''',
)
