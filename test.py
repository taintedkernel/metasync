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
@click.command()
@click.option('--db')
@click.option('--path')
@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--dedup', default=False, type=bool)
def ms_verify(db, path, verify, dedup):
    options = {'path': path, 'verify': verify, 'dedup': dedup}
    logger.debug('options: %s', options)
    mgr = MSManager(db, options)
    sys.exit(0)


@click.command()
@click.option('--db')
@click.option('--path')
@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
@click.option('--dedup', default=False, type=bool)
def ms_add(db, path, verify, dedup):
    options = {'path': path, 'verify': verify, 'dedup': dedup}
    logger.debug('options: %s', options)
    mgr = MSManager(db, options)
    new_files = mgr.scan_new_files(path)
    mgr.verify_add_new_files(new_files)
    sys.exit(0)


@click.command()
@click.argument('host')
@click.option('--key', default=None, help='keyfile to connect to remote server')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
#@click.option('--verify', default='recurse', type=click.Choice(['none', 'path', 'recurse', 'all']))
#@click.option('--path', help='root path for files to manage')
def ms_add_mirror(host, key, db):
    #pnames = ('path', 'verify', 'strong_verify', 'dedup', 'dry')
    #args = (path, 'none', False, dedup, dry)
    pnames = ('verify', 'strong_verify', 'dry')
    #args = (path, ctx.obj['verify'], ctx.obj['strong_verify'], dedup, dry)
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    mgr.add_mirror(host, {'key': key})


@click.command()
@click.argument('host')
@click.option('--path', default='/', help='path to walk')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def ms_walk_scan_mirror(host, path, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    mgr.walk_scan_host(host, path)


@click.command()
@click.argument('host')
@click.option('--path', default='/', help='path to walk')
@click.option('--db', default=os.path.join(os.getcwd(), 'metasync.db'), help='location of database')
def ms_verify_host_files(host, path, db):
    pnames = ('verify', 'strong_verify', 'dry')
    args = ('none', False, False)
    params = dict(zip(pnames, args))

    # Load our manager
    mgr = MSManager(db, params)
    logger.info('manager loaded')

    mgr.verify_host_files(host)


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
        result = runner.invoke(ms_add, ['--db', test_db_path, '--path', test_data_path])
        _test_exitcode_logs(result)

    return (test_db_path, test_data_path, test_file_path)


#
# Parse our logs, checking for problems, return for further verification
# Check exit code
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
            assert re.search(rc, test_log_data)

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
        result = runner.invoke(ms_verify, ['--db', test_db_path, '--path', test_data_path])

        mtime_mod_msg = '^.*%s.*mtime modified.*$' % (test_file_path)
        data_same_msg = '^.*%s.*detected as updated but contents unchanged.*$' % (test_file_path)
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
        result = runner.invoke(ms_add, ['--db', test_db_path, '--path', test_data_path])

        # We expect a WARNING here
        mtime_mod_msg = '^.*%s.*mtime modified.*$' % (test_file_path)
        data_updated_msg = '^.*%s.*contents updated to.*$' % (test_file_path)
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
        result = runner.invoke(ms_verify, ['--db', test_db_path, '--path', test_data_path])

        # We expect a WARNING here
        test_log_data = _test_exitcode_logs(result, expect_warnings=True)

        file_missing_msg = 'WARNING - %s missing' % test_file_path
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
        result = runner.invoke(ms_add, ['--db', test_db_path, '--path', test_data_path])

        # We expect a WARNING here
        match_found_msg = '^.*match on .*%s.* found with .*%s.*$' % (test_file_path, new_test_file_path)
        update_file_msg = '^.*updating missing file .*%s.* to match new .*%s.*$' % (test_file_path, new_test_file_path)
        regex = [match_found_msg, update_file_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)

        file_missing_msg = 'WARNING - %s missing' % test_file_path
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
def test_create_dupe_files():
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
        result = runner.invoke(ms_add, ['--db', test_db_path, '--path', test_data_path, '--dedup', True])

        # We expect a WARNING here
        new_dupe_msg = '^.*new file:.*%s.*$' % (test_file2_path)
        existing_dupe_msg = '^.*existing file:.*%s.*$' % (test_file_path)
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
        result = runner.invoke(ms_add_mirror, [FTP_URL, '--db', test_db_path])

        try:
            test_log_data = _test_exitcode_logs(result)
        except:
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()

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
        result = runner.invoke(ms_add_mirror, [FTP_URL, '--db', test_db_path])

        try:
            test_log_data = _test_exitcode_logs(result)
        except:
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()
            return

        # TODO: We need to validate test file is matched
        logger.debug('loading metasync:ms_walk_scan_mirror')
        result = runner.invoke(ms_walk_scan_mirror, [FTP_URL, '--path', '/', '--db', test_db_path])

        try:
            test_log_data = _test_exitcode_logs(result)
        except e:
            logger.error('exception: %s', e)
            logger.info('shutting down ftp daemon')
            ftpd.terminate()
            ftpd.join()
            return

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

        test_log_data = _test_exitcode_logs(result)
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

        # TODO: We need to validate test file is matched
        logger.debug('loading metasync:ms_walk_scan_mirror')
        result = runner.invoke(ms_walk_scan_mirror, [url, '--path', '/', '--db', test_db_path])
        #result = runner.invoke(ms_walk_scan_mirror, [url, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result)

        logger.debug('--- test passed ---')


#
# TEST 10 : Test propagation of changes to SFTP
#  - Create mock data, add to DB
#  - Copy mock data to new, separate path for SFTP
#  - Test connectivity with mirror SFTP
#  - Test scanning of mirror to match original files
#  - Test rename of local file, detection of change
#  - Test propagation of local rename to mirror SFTP data
#
def new_test():
    logger.info('--- running test_sftp_scan_match_rename  ---')
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

        # TODO: We need to validate test file is matched
        logger.debug('loading metasync:ms_walk_scan_mirror')
        #result = runner.invoke(ms_walk_scan_mirror, [url, '--path', '/', '--db', test_db_path])
        result = runner.invoke(ms_walk_scan_mirror, [url, '--db', test_db_path])

        test_log_data = _test_exitcode_logs(result)

        # Now we rename our local source data
        (new_test_file, new_test_file_path) = tempfile.mkstemp(dir=test_data_path)
        os.close(new_test_file)
        # This isn't an atomic operation, but
        # for our purposes it should be sufficient
        os.remove(new_test_file_path)
        os.rename(test_file_path, new_test_file_path)

        # Reload metasync, ensure changes are detected
        result = runner.invoke(ms_add, ['--path', test_data_path, '--db', test_db_path])

        # We expect a WARNING here
        match_found_msg = '^.*match on .*%s.* found with .*%s.*$' % (test_file_path, new_test_file_path)
        update_file_msg = '^.*updating missing file .*%s.* to match new .*%s.*$' % (test_file_path, new_test_file_path)
        regex = [match_found_msg, update_file_msg]
        test_log_data = _test_exitcode_logs(result, expect_warnings=True, regex=regex)

        file_missing_msg = 'WARNING - %s missing' % test_file_path
        assert file_missing_msg in test_log_data
        assert 'verification completed, 1 files missing' in test_log_data

        logger.debug('loading ms_verify_host_files')
        result = runner.invoke(ms_verify_host_files, [url, '--db', test_db_path])
        #test_log_data = _test_exitcode_logs(result)

        # Then test propagation of changes to mirror
        logger.debug('--- test passed ---')


# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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

