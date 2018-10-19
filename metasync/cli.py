import click
import dateutil.parser

from datetime import datetime
import time

import logging
import sys
import os

from metasync.manager import MSManager


LOG_FILE = 'metasync-{date}.log'


### Having issues getting this working, will revisit later ###
#@click.group()
#@click.pass_context
#@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
#@click.option('--strong_verify', default=False, type=bool,
#              help='recomputes hashes to verify contents unchanged (guards against data corruption)')
#def cli(ctx, db, verify, strong_verify):
#    ctx.obj['db'] = db
#    ctx.obj['verify'] = verify
#    ctx.obj['strong_verify'] = strong_verify


#@click.pass_context
@click.command()
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='all', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool,
              help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--path', help='root path for files to manage')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def ep_verify(db, verify, strong_verify, path, dedup, dry):
    # A better way exists, but this works for the moment
    # Dry-run partially works, it shouldn't update the files table
    #   but history is still changed.  We should do some sort of
    #   wrapper to prevent modifications to do it properly.
    pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = (path, verify, strong_verify, dedup, dry)
    params = dict(zip(pnames, args))

    # Load our manager
    MSManager(db, params)
    logger.info('manager loaded')


@click.command()
@click.argument('start')
@click.option('--end', default=datetime.now().strftime('%c'))
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--path', help='root path for files to manage')
@click.option('--verify', default='all', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool,
              help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--path', help='root path for files to manage')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def ep_show_history(start, end, db, path, verify, strong_verify, dedup, dry):
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


@click.command()
@click.argument('path')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--strong_verify', default=False, type=bool,
              help='recomputes hashes to verify contents unchanged (guards against data corruption)')
@click.option('--dedup', default=False, type=bool, help='enable deduplication detection')
@click.option('--dry', default=False, type=bool, help='dry run (no changes)')
def ep_add_path(path, db, verify, strong_verify, dedup, dry):
    # TODO: will not work for a sub-path, treats as a new location and adds files
    # despite existing in another repo
    pnames = ('db', 'verify', 'strong_verify', 'dedup', 'dry', 'create_missing_repo')
    args = (db, verify, strong_verify, dedup, dry, True)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, path, params)
    logger.info('manager loaded')

    repo = mgr.add_repo(path)
    new_files = mgr.scan_new_files()
    mgr.verify_add_new_files(new_files)
    # TODO: update repo status from 'new'


@click.command()
@click.argument('host')
@click.option('--key', help='keyfile to connect to remote server')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def ep_add_mirror(host, key, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    credentials = {'key': key} if key else {}
    mgr.add_mirror(host, credentials)


@click.command()
@click.argument('host')
@click.option('--path', help='path to walk')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def ep_walk_scan_mirror(host, path, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    mgr.walk_scan_mirror(host, path)
    #mirror = mgr.get_mirror(host)
    #mirror.connect()
    #for mpath, mdirs, mfiles in mirror.walk(path):
    #    for mfile in mfiles:
    #        mfile_path = os.path.join(mpath, mfile)
    #        size = mirror.get_size(mfile_path)
    #        mtime = mirror.get_mtime(mfile_path)
    #        logger.info('found mirror file %s, size %d, time %s', mfile, size, mtime)


def ep_mirror_sync(db, path, verify_all):
    pass


# Configure logging
# using __name__ prevents logs in other files from displaying
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

now = datetime.now().replace(microsecond=0).isoformat()
log_file = os.path.join(os.getcwd(), LOG_FILE.format(date=now))
fh = logging.FileHandler(log_file)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
#f = ContextFilter()
#fh.addFilter(f)
logger.addHandler(fh)

logger.info('logger initialized')

