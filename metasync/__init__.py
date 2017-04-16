import click
import dateutil.parser

from datetime import datetime
import time

import logging
import sys
import os

#import MSManager
from metasync import MSManager


### Having issues getting this working, will revisit later ###
#@click.group()
#@click.pass_context
#@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
#@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
#def cli(ctx, db, verify, strong_verify):
#    ctx.obj['db'] = db
#    ctx.obj['verify'] = verify
#    ctx.obj['strong_verify'] = strong_verify


#@click.pass_context
@click.command()
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='all', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--path', help='root path for files to manage')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def verify(db, verify, strong_verify, path, dedup, dry):
    # A better way exists, but this works for the moment
    # Dry-run partially works, it shouldn't update the files table
    #   but history is still changed.  We should do some sort of
    #   wrapper to prevent modifications to do it properly.
    pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = (path, verify, strong_verify, dedup, dry)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    sys.exit(0)


@click.command()
@click.argument('start')
@click.option('--end', default=datetime.now().strftime('%c'))
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--path', help='root path for files to manage')
@click.option('--verify', default='all', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--path', help='root path for files to manage')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def show_history(start, end, db, path, verify, strong_verify, dedup, dry):
    pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = (path, verify, strong_verify, dedup, dry)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    start_dt = dateutil.parser.parse(start)
    end_dt = dateutil.parser.parse(end)

    mgr.build_diff(start_dt, end_dt)


#@cli.command()
@click.command()
@click.argument('path')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--path', help='root path for files to manage')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def add_path(db, verify, strong_verify, path, dedup, dry):
    pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = (path, verify, strong_verify, dedup, dry)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    new_files = mgr.scan_new_files(path)
    mgr.verify_add_new_files(new_files)
    sys.exit(0)


@click.command()
@click.argument('host')
@click.option('--connection', help='parameters to establish connection')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
#@click.option('--strong_verify', default=False, type=bool, help='recomputes hashes to verify contents unchanged (guards against data corruption)')
#@click.option('--path', help='root path for files to manage')
#@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
#def add_mirror(host, connection, db, path, dedup, dry):
def add_mirror(host, connection, db, dry):
    #pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, 'none', False, dedup, dry)
    pnames = ('verify', 'strong_verify', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = ('none', False, dry)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    mgr.add_mirror(host)
    sys.exit(0)


def mirror_sync(db, path, verify_all):
    pass


# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.info('logger initialized')

