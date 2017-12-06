import multiprocessing
import tempfile
import logging
import logging.handlers
import shutil
import time
import sys
import os
import re

import click
from click.testing import CliRunner

import colorlog

from metasync.manager import MSManager


### Constants ###
TEST_DB = 'test.db'
TEST_LOG = 'test.log'

FTP_URL = 'ftp://localhost:2121'
SFTP_URL = 'sftp://localhost{path}'
SSH_KEY = '{home}/.ssh/id_localhost_test'.format(home=os.path.expandvars('$HOME'))


# Filter for our logger
class ContextFilter(logging.Filter):
    def filter(self, record):
        if 'metasync' in record.name:
            return True
        return False


### Invocations ###
# Verify existing files in DB
@click.command()
@click.option('--repo', help='root repository to use')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='all', type=click.Choice(['none', 'all']))
@click.option('--dedup', default=False, type=bool)
def ms_verify(repo, db, verify, dedup):
    params = {'verify': verify, 'dedup': dedup}

    mgr = MSManager(db, repo, params)
    logger.info('manager loaded')

    sys.exit(0)


# Scan for new files, verify these then add to DB
@click.command()
@click.option('--repo', help='root repository to use')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
@click.option('--verify', default='all', type=click.Choice(['none', 'all']))
@click.option('--dedup', default=False, type=bool)
def ms_add(repo, db, verify, dedup):
    params = {'verify': verify, 'dedup': dedup, 'create_missing_repo': True}

    mgr = MSManager(db, repo, params)
    logger.info('manager loaded')

    new_files = mgr.scan_new_files()
    mgr.verify_add_new_files(new_files)

    sys.exit(0)


# Create new mirror
@click.command()
@click.argument('host')
@click.option('--key', default=None, help='keyfile to connect to remote server')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
#@click.option('--path', help='root path for files to manage')
def ms_add_mirror(host, key, db):
    pnames = ('verify', 'strong_verify', 'dry', 'mgr_no_repo')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = ('none', False, False, True)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, None, params)
    logger.info('manager loaded')

    mgr.add_mirror(host, {'key': key})


# Scan mirror for new files
# Check new files against existing files in DB, add if match
@click.command()
@click.argument('url')
@click.option('--repo', help='root repository to use')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def ms_walk_scan_mirror(url, repo, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, repo, params)
    logger.info('manager loaded')

    mgr.walk_scan_host(url)


# Iterate through files stored on a mirror and verify status
@click.command()
@click.argument('url')
@click.option('--repo', help='root repository to use')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--path', default='/', help='path to walk')
#def ms_verify_host_files(host, path, db):
def ms_verify_update_host_files(url, repo, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, repo, params)
    logger.info('manager loaded')

    mgr.verify_update_host_files(url)


##### Helper functions #####

#
# Setup and run FTP server
#
def _setup_ftpd(path):
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler
    from pyftpdlib.servers import FTPServer

    authorizer = DummyAuthorizer()
    authorizer.add_anonymous(path)

    handler = FTPHandler
    handler.authorizer = authorizer

    logger.info('invoking pyftpdlib on path %s', path)
    ftplog = logging.getLogger('pyftpdlib')
    ftplog.setLevel(logging.INFO)
    server = FTPServer(("127.0.0.1", 2121), handler)
    server.serve_forever()


#
# Configure app logging to file (to read from later)
# Create mock data files
#
def _setup_log_mock_data(runner, invoke=True):

    # Create new directory, write some temp data
    # eg: <isolated_fs>/files/tmpfileXXX
    logger.debug('creating mock file data')
    test_db_path = os.path.join(os.getcwd(), TEST_DB)
    test_data_path = os.path.join(os.getcwd(), 'files')
    if not os.path.exists(test_data_path):
        os.mkdir(test_data_path)
    (test_file, test_file_path) = tempfile.mkstemp(dir=test_data_path)
    os.write(test_file, os.urandom(1024))
    os.close(test_file)

    # Clear the log state
    # We "regex-the-logs" in our unittests,
    # wonderful I know.
    if os.path.exists(test_log_path):
        os.unlink(test_log_path)

    if invoke:
        logger.debug('loading metasync:ms_add')
        result = runner.invoke(ms_add, ['--db', test_db_path, '--repo', test_data_path], catch_exceptions=False)
        _test_exitcode_logs(result)

    logger.debug('setup completed')
    return (test_db_path, test_data_path, test_file_path)


#
# Parse our logs, checking for problems, return for further verification
# Check exit code
#
# TODO: Ideally, we should have ability to check portion of logs,
#   from the most recent check until now to have finer-grained control
#   of checking levels
#
def _test_exitcode_logs(result, expect_warnings=False, regex=None):
    logger.debug('result: %s', result)
    assert result.exit_code == 0

    # Gather our logs
    with open(test_log_path, 'r') as log_file_h:
        test_log_data = ''.join(log_file_h.readlines())

    levels = ['ERROR', 'CRITICAL']
    if not expect_warnings:
        levels.append('WARNING')
    assert not any(map(lambda x: x in test_log_data, levels))

    if regex:
        for r in regex:
            rc = re.compile(r, re.M)
            try:
                assert re.search(rc, test_log_data)
            except AssertionError, e:
                logger.critical('unable to match regex %s', r)
                raise e

    return test_log_data


##### Unit tests #####


#
# TEST 1 : Test update metadata detection:
#  - Create new temp file in "path", add to DB, then rewrite file with same data
#    This will update mtime but leave sha256 the same, test this is detected correctly
#
def test_detect_updated_metadata():
    logger.info('--- running detect_updated_metadata test ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Do our test operation
        logger.debug('editing mock file %s', test_file_path)
        time.sleep(1)       # Help ensure timestamp comparison works
        with open(test_file_path, 'r+b') as f:
            test_file_data = f.read(1024)
            f.seek(0)
            f.write(test_file_data)

        # Test successful detection
        logger.debug('loading metasync:ms_verify')
        result = runner.invoke(ms_verify, ['--db', test_db_path, '--repo', test_data_path])

        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        mtime_mod_msg = '^.*%s.*mtime modified.*$' % (l_test_file_path)
        data_same_msg = '^.*%s.*detected as updated but contents unchanged.*$' % (l_test_file_path)
        regex = [mtime_mod_msg, data_same_msg]
        test_log_data = _test_exitcode_logs(result, regex=regex)

        assert 'verification completed, all files accounted for' in test_log_data
        logger.info('--- test passed ---')


#
# TEST 2: Test update metadata detection:
#  - Create new temp file in "path", add to DB, then rewrite file with random/new data
#    This will update mtime and sha256, test this is detected correctly
#
def test_detect_updated_data():
    logger.info('--- running detect_updated_data test ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Do our test operation
        logger.debug('editing mock file %s', test_file_path)
        time.sleep(1)       # Help ensure timestamp comparison works
        with open(test_file_path, 'r+b') as f:
            f.seek(0)
            f.write(os.urandom(1024))

        # Test successful detection
        logger.debug('loading metasync:ms_add')
        result = runner.invoke(ms_add, ['--db', test_db_path, '--repo', test_data_path], catch_exceptions=False)

        # We expect a WARNING here
        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        mtime_mod_msg = '^.*%s.*mtime modified.*$' % (l_test_file_path)
        data_updated_msg = '^.*%s.*contents updated to.*$' % (l_test_file_path)
        regex = [mtime_mod_msg, data_updated_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)

        assert 'verification completed, all files accounted for' in test_log_data
        logger.info('--- test passed ---')


#
# TEST 3: Test missing file detection:
#  - Create new temp file in "path", add to DB, then remove
#
def test_detect_missing_files():
    logger.info('--- running detect_missing_files test ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Do our test operation
        logger.debug('removing mock file')
        os.unlink(test_file_path)

        # Test successful detection
        logger.debug('loading metasync:ms_verify')
        result = runner.invoke(ms_verify, ['--db', test_db_path, '--repo', test_data_path], catch_exceptions=False)

        # We expect a WARNING here
        test_log_data = _test_exitcode_logs(result, expect_warnings=True)

        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        file_missing_msg = 'WARNING - %s missing' % l_test_file_path
        assert file_missing_msg in test_log_data
        assert 'verification completed, 1 files missing' in test_log_data
        logger.info('--- test passed ---')


#
# TEST 4 : Test moved file detection:
#  - Create new temp file in "path", then create subfolder, move temp file
#
def test_detect_moved_files():
    logger.info('--- running detect_moved_file test ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Do our test operation
        tmp_path = os.path.join(test_data_path, 'tmpdir')
        new_test_file_path = os.path.join(tmp_path, os.path.basename(test_file_path))
        logger.debug('creating new temporary directory %s', tmp_path)
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)
        logger.debug('moving %s to %s', test_file_path, new_test_file_path)
        shutil.move(test_file_path, new_test_file_path)

        # Test successful detection
        logger.debug('loading metasync:ms_add')
        result = runner.invoke(ms_add, ['--db', test_db_path, '--repo', test_data_path], catch_exceptions=False)

        # We expect a WARNING here
        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        l_new_test_file_path = os.path.relpath(new_test_file_path, test_data_path)
        match_found_msg = '^.*match on .*%s.* found with .*%s.*$' % (l_test_file_path, l_new_test_file_path)
        update_file_msg = '^.*updating missing file .*%s.* to match new .*%s.*$' % (l_test_file_path, l_new_test_file_path)
        regex = [match_found_msg, update_file_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)

        file_missing_msg = 'WARNING - %s missing' % l_test_file_path
        assert file_missing_msg in test_log_data
        assert 'verification completed, 1 files missing' in test_log_data
        logger.info('--- test passed ---')


#
# TODO: Do we do a rename file here?  This is common as well,
# but should look like a move operation and testing that
# as above may be sufficient
#
def test_detect_renamed_files():
    logger.info('--- running detect_renamed_file test ---')
    logger.info('skipping test, covered in theory by test_detect_moved_files')
    logger.info('--- test skipped/ended ---')


#
# TEST 5 : Dedupe functionality:
#  - Create new temp file in "path", copy to new temp file in same path
#
def test_detect_dupe_files():
    logger.info('--- running create_dupe_files test ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Do our test operation
        (test_file2, test_file2_path) = tempfile.mkstemp(dir=test_data_path)
        os.close(test_file2)
        logger.debug('created %s, copying to %s', test_file_path, test_file2_path)
        shutil.copy(test_file_path, test_file2_path)

        # Test successful detection
        logger.debug('loading metasync:ms_add')
        result = runner.invoke(ms_add, ['--db', test_db_path, '--repo', test_data_path, '--dedup', True], catch_exceptions=False)

        # We expect a WARNING here
        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        l_test_file2_path = os.path.relpath(test_file2_path, test_data_path)
        new_dupe_msg = '^.*new file:.*%s.*$' % (l_test_file2_path)
        existing_dupe_msg = '^.*existing file:.*%s.*$' % (l_test_file_path)
        regex = [new_dupe_msg, existing_dupe_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)

        assert 'duplicate file detected' in test_log_data
        assert 'verification completed, all files accounted for' in test_log_data
        logger.info('--- test passed ---')


#
# TEST 6 : Test FTP client
#  - Spawn FTP server as separate process
#  - Test connectivity with mirror FTP
#
def test_ftp_connect():
    logger.info('--- running test_ftp_connect ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner, invoke=False)
        ftpd = multiprocessing.Process(target=_setup_ftpd, args=(test_data_path,))
        logger.info('spawning ftp daemon')
        ftpd.start()

        time.sleep(2)
        logger.debug('loading metasync:ms_add_mirror')
        try:
            result = runner.invoke(ms_add_mirror, [FTP_URL, '--db', test_db_path], catch_exceptions=False)
            test_log_data = _test_exitcode_logs(result)
        finally:
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()

        logger.debug('--- test passed ---')


#
# TEST 7 : Test scanning and matching via FTP
#  - Create mock data, add to DB
#  - Copy mock data to new, separate path
#  - Spawn FTP server as separate process under new path
#  - Test connectivity with mirror FTP
#  - Test scanning of mirror to match original files
#
def test_ftp_scan_match():
    logger.info('--- running test_ftp_scan_match ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Create new temp directory and copy file
        tmp_path = os.path.join(test_data_path, 'tmpdir')
        new_test_file_path = os.path.join(tmp_path, os.path.basename(test_file_path))
        logger.debug('creating new temporary directory %s', tmp_path)
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)
        logger.debug('copying %s to %s', test_file_path, new_test_file_path)
        shutil.copy(test_file_path, new_test_file_path)

        ftpd = multiprocessing.Process(target=_setup_ftpd, args=(tmp_path,))
        logger.info('spawning ftp daemon')
        ftpd.start()

        time.sleep(2)
        logger.debug('loading metasync:ms_add_mirror')
        url = FTP_URL
        result = runner.invoke(ms_add_mirror, [url, '--db', test_db_path], catch_exceptions=False)

        try:
            test_log_data = _test_exitcode_logs(result, expect_warnings=True)
        except:
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()
            return

        # TODO: We need to actually validate test file is matched
        # Currently we just ensure no invalid log messages occur
        logger.debug('loading metasync:ms_walk_scan_mirror')
        try:
            result = runner.invoke(ms_walk_scan_mirror, [url, '--repo', test_data_path, '--db', test_db_path], catch_exceptions=False)
            test_log_data = _test_exitcode_logs(result, expect_warnings=True)
        finally:
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()

        logger.debug('--- test passed ---')


#
# TEST 8 : Test SFTP client
#  - Test connectivity with mirror SFTP
#
def test_sftp_connect():
    logger.info('--- running test_sftp_connect ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner, invoke=False)

        # Create new temp directory
        tmp_path = os.path.join(test_data_path, 'tmpdir')
        logger.debug('creating new temporary directory %s', tmp_path)
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)

        logger.debug('loading metasync:ms_add_mirror')
        url = SFTP_URL.format(path=tmp_path)
        result = runner.invoke(ms_add_mirror, [url, '--key', SSH_KEY, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result, expect_warnings=True)
        logger.debug('--- test passed ---')


#
# TEST 9 : Test scanning and matching via SFTP
#  - Create mock data, add to DB
#  - Copy mock data to new, separate path for SFTP
#  - Test connectivity with mirror SFTP
#  - Test scanning of mirror to match original files
#
def test_sftp_scan_match():
    logger.info('--- running test_sftp_scan_match ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Create new temp directory and copy file
        tmp_path = os.path.join(test_data_path, 'tmpdir')
        new_test_file_path = os.path.join(tmp_path, os.path.basename(test_file_path))
        logger.debug('creating new temporary directory %s', tmp_path)
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)
        logger.debug('copying %s to %s', test_file_path, new_test_file_path)
        shutil.copy(test_file_path, new_test_file_path)

        time.sleep(2)
        logger.debug('loading metasync:ms_add_mirror')
        url = SFTP_URL.format(path=tmp_path)
        result = runner.invoke(ms_add_mirror, [url, '--key', SSH_KEY, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result)

        # TODO: We need to actually validate test file is matched
        # Currently we just ensure no invalid log messages occur
        logger.debug('loading metasync:ms_walk_scan_mirror')
        result = runner.invoke(ms_walk_scan_mirror, [url, '--repo', test_data_path, '--db', test_db_path])
        #result = runner.invoke(ms_walk_scan_mirror, [url, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result)

        logger.debug('--- test passed ---')


#
# TEST 10 : Test propagation of changes to SFTP
#  - Create mock data, add to DB
#  - Copy mock data to new, separate path for SFTP
#  - Test connectivity with mirror SFTP
#  - Test scanning of mirror to match original files (simulate mirror copy)
#  - Test rename of local file, detection of change
#  - Test identification of local rename not propagated to mirror (out-of-sync)
#  - Test propagation of local rename to mirror SFTP data
#

# test_db_path          = <isolated_fs>/test.db
# test_data_path        = <isolated_fs>/files/
# test_file_path        = <isolated_fs>/files/tmpfileXXX

# sftp_path             = <isolated_fs>/sftp_path/
# new_test_file_path    = <isolated_fs>/sftp_path/tmpfileXXX

# copy first test file to sftp path for mirror copy
# cp
#   <isolated_fs>/files/tmpfileXXX
#   <isolated_fs>/sftp_path/tmpfileXXX

# make mirror at sftp_path, add data copied above

# rename existing test file to new name
# new_test_file_path    = <isolated_fs>/files/tmpfileYYY
# mv
#   <isolated_fs>/files/tmpfileXXX
#   <isolated_fs>/flies/tmpfileYYY

def test_sftp_scan_match_rename():
    logger.info('--- running test_sftp_scan_match_rename  ---')
    runner = CliRunner()
    with runner.isolated_filesystem():
        # test_db_path = <isolated_fs>/test.db
        # test_data_path = <isolated_fs>/files/
        # test_file_path = <isolated_fs>/files/tmpfileXXX
        (test_db_path, test_data_path, test_file_path) = _setup_log_mock_data(runner)

        # Create new temp directory and copy file
        # sftp_path = <isolated_fs>/sftp_dir/
        # new_test_file_path = <isolated_fs>/sftp_dir/tmpfileXXX
        sftp_path = os.path.join(os.getcwd(), 'sftp_dir')
        new_test_file_path = os.path.join(sftp_path, os.path.basename(test_file_path))
        logger.debug('creating new temporary directory %s', sftp_path)
        if not os.path.exists(sftp_path):
            os.mkdir(sftp_path)
        logger.debug('copying %s to %s', test_file_path, new_test_file_path)
        # eg:
        # cp <isolated_fs>/files/tmpfileXXX <isolated_fs>/sftp_dir/tmpfileXXX
        shutil.copy(test_file_path, new_test_file_path)

        # Ensure file copy finished
        time.sleep(2)

        # Create mirror at <isolated_fs>/sftp_dir/
        logger.debug('loading metasync:ms_add_mirror')
        url = SFTP_URL.format(path=sftp_path)
        result = runner.invoke(ms_add_mirror, [url, '--key', SSH_KEY, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result, expect_warnings=True)

        # TODO: We need to actually validate test file is matched
        # Currently we just ensure no invalid log messages occur
        logger.debug('loading metasync:ms_walk_scan_mirror')
        result = runner.invoke(ms_walk_scan_mirror, [url, '--repo', test_data_path, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result)

        # Now we rename our local source data
        logger.info('renaming local source data')
        # new_test_file_path = <isolated_fs>/files/tmpfileYYY
        (new_test_file, new_test_file_path) = tempfile.mkstemp(dir=test_data_path)
        os.close(new_test_file)
        # This isn't an atomic operation, but
        # for our purposes it should be sufficient
        os.remove(new_test_file_path)
        os.rename(test_file_path, new_test_file_path)
        # eg: mv <isolated_fs>/files/tmpfileXXX <isolated_fs>/files/tmpfileYYY
        logger.debug('moved %s to %s', test_file_path, new_test_file_path)

        # Reload metasync, ensure rename is detected
        logger.debug('loading metasync:ms_add')
        result = runner.invoke(ms_add, ['--repo', test_data_path, '--db', test_db_path])

        # Test, we expect a WARNING here
        l_test_file_path = os.path.relpath(test_file_path, test_data_path)
        l_new_test_file_path = os.path.relpath(new_test_file_path, test_data_path)
        match_found_msg = '^.*match on .*%s.* found with .*%s.*$' % (l_test_file_path, l_new_test_file_path)
        update_file_msg = '^.*updating missing file .*%s.* to match new .*%s.*$' % (l_test_file_path, l_new_test_file_path)
        regex = [match_found_msg, update_file_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)
        file_missing_msg = 'WARNING - %s missing' % l_test_file_path
        assert file_missing_msg in test_log_data
        assert 'verification completed, 1 files missing' in test_log_data

        # Propagate changes to mirror!
        logger.debug('loading ms_verify_update_host_files')
        result = runner.invoke(ms_verify_update_host_files, [url, '--repo', test_data_path, '--db', test_db_path])
        renaming_msg = '^.*renaming mirror %s to match local %s.*$' % (l_test_file_path, l_new_test_file_path)
        # We don't expect warnings in the call to ms_verify_update_host_files,
        # but this function checks the entire log and we do not have a mechanism
        # to test a subset of logs currently (we expected warnings above)
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=[renaming_msg])

        # Test propagation of changes
        logger.debug('re-loading ms_verify_update_host_files')
        result = runner.invoke(ms_verify_update_host_files, [url, '--repo', test_data_path, '--db', test_db_path])
        up2date_msg = '^.*mirror up to date with local.*%s' % (l_new_test_file_path)
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex = [up2date_msg])

        logger.debug('--- test passed ---')


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
#ch = logging.StreamHandler()
ch = colorlog.StreamHandler()
ch.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s - %(name)s:%(lineno)d - %(levelname)s - %(message)s')
formatter = colorlog.ColoredFormatter('%(asctime)s - %(name)20s:%(lineno)-4d - %(log_color)s%(levelname)-7s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


# We also log to file so the tests can read log messages
# and verify functionality.  Not an ideal way, but works
# and better then nothing!
test_log_path = os.path.join(os.getcwd(), TEST_LOG)
fh = logging.handlers.WatchedFileHandler(test_log_path)
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
#f = ContextFilter()
#fh.addFilter(f)
logger.addHandler(fh)


if __name__ == '__main__':
    test_detect_updated_metadata()
    test_detect_updated_data()
    test_detect_missing_files()
    test_detect_moved_files()
    test_create_dupe_files()
    test_ftp_connect()
    test_ftp_scan_match()

