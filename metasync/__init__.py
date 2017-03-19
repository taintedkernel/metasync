import click

from datetime import datetime
import time

import logging
import sys
import os

#import MSManager
from metasync import MSManager


@click.command()
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--path', help='root path for files to manage')
@click.option('--update', default=True, type=bool, help='update data on changed files')
@click.option('--verify_all', default=True, type=bool, help='verify files in db')
@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
def scan(db, path, update, verify_all, strong_verify, dedup):
    # Load our manager
    mgr = MSManager()
    logger.info('manager loaded')

    # A better way exists, but this works for the moment
    pnames = ('path', 'update', 'verify_all', 'strong_verify', 'dedup')
    args = (path, update, verify_all, strong_verify, dedup)
    params = dict(zip(pnames, args))
    mgr.init(db, params)

    mgr.scan_path()

    sys.exit(0)


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

