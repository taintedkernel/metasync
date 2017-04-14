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
        'nose'
    ],
    entry_points='''
        [console_scripts]
        ms_verify=metasync:verify
        ms_show_history=metasync:show_history
        ms_add_path=metasync:add_path
        ms_add_mirror=metasync:add_mirror
    ''',
)
